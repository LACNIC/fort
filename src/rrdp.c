#include "rrdp.h"

#include <errno.h>
#include <openssl/err.h>
#include <sys/queue.h>

#include "base64.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "rrdp_xml.h"
#include "types/fnstack.h"

struct rrdp_step {
	struct rrdp_serial serial;
	struct files_ht files;
	struct rrdp_hash delta_hash;
	TAILQ_ENTRY(rrdp_step) lh;	/* List hook */
};

TAILQ_HEAD(rrdp_steps, rrdp_step);

struct rrdp_ctx {
	char *session_id;

	/*
	 * The 1st one is the session.serial snap.
	 * The 2nd one is the session.serial - 1 snap.
	 * The 3rd one is the session.serial - 2 snap.
	 * And so on.
	 */
	struct rrdp_steps steps;
	/* Hash table, indexed by rpkiMft */
	struct fallback_ht fbs;
	/* For file names */
	struct cache_sequence seq;

	/* Refresh successful during this cycle? */
	bool success;

	/* Steps that have been queued to be deleted later */
	struct rrdp_steps postponed_steps;
	/* Files that have been queued to be deleted later */
	struct files_stailq postponed_files;
};

enum rrdp_dao_state {
	RDS_STEP,
	RDS_FB,
	RDS_DONE,
};

struct rrdp_dao {
	struct uri rpkiManifest;
	struct rrdp_ctx *ctx;
	enum rrdp_dao_state state;

	struct rrdp_step *step;
	struct fallback *fb;
};

/* A deserialized <publish> tag, from a snapshot or delta. */
struct publish {
	struct file_metadata meta;
	unsigned char *content;
	size_t content_len;
};

/* A deserialized <withdraw> tag, from a delta. */
struct withdraw {
	struct file_metadata meta;
};

static struct rrdp_step *
step_create(struct rrdp_serial *serial)
{
	struct rrdp_step *step;

	step = pmalloc(sizeof(struct rrdp_step));
	serial_copy(&step->serial, serial);
	step->files.ht = NULL;
	step->delta_hash.set = false;

	return step;
}

static void
step_free(struct rrdp_step *step, bool rm_files)
{
	pr_trc("Dropping step: %s", step->serial.str);
	filerefs_clear(&step->files, rm_files);
	serial_cleanup(&step->serial);
	free(step);
}

static void
steps_clear(struct rrdp_steps *steps, bool rm_files)
{
	struct rrdp_step *step;

	while ((step = TAILQ_FIRST(steps)) != NULL) {
		TAILQ_REMOVE(steps, step, lh);
		step_free(step, rm_files);
	}
}

/* Moves all the steps from @src to the tail of @dst. */
static void
steps_transfer(struct rrdp_steps *dst, struct rrdp_steps *src)
{
	struct rrdp_step *step;

	/* TODO (performance) This is O(n); could be O(1). */
	while ((step = TAILQ_FIRST(src)) != NULL) {
		TAILQ_REMOVE(src, step, lh);
		TAILQ_INSERT_TAIL(dst, step, lh);
	}
}

static void
init_steps(struct rrdp_steps *steps, struct update_notification *notif)
{
	struct notification_delta *delta;
	struct rrdp_step *step;
	unsigned int d;

	TAILQ_INIT(steps);

	for (d = 0; d < notif->deltas.len; d++) {
		delta = &notif->deltas.arr[d];

		if (d++ > RRDP_DELTA_THRESHOLD)
			break;

		step = pmalloc(sizeof(struct rrdp_step));
		serial_copy(&step->serial, &delta->serial);
		step->files.ht = NULL;
		step->delta_hash = delta->meta.hash;
		TAILQ_INSERT_TAIL(steps, step, lh);
	}
}

/* Caution: Does not initialize seq. */
static struct rrdp_ctx *
rrdpctx_create(void)
{
	struct rrdp_ctx *ctx;

	ctx = pzalloc(sizeof(struct rrdp_ctx));
	TAILQ_INIT(&ctx->steps);
	panic_on_fail(pthread_mutex_init(&ctx->fbs.lock, NULL),
	    "pthread_mutex_init");
	TAILQ_INIT(&ctx->postponed_steps);
	STAILQ_INIT(&ctx->postponed_files);

	return ctx;
}

/* "Free from memory." Does not extend to the cache files. */
void
rrdpctx_free(struct rrdp_ctx *ctx)
{
	if (ctx == NULL)
		return;

	free(ctx->session_id);
	steps_clear(&ctx->steps, false);
	fallbacks_cleanup(&ctx->fbs, false);
	cseq_cleanup(&ctx->seq);
	steps_clear(&ctx->postponed_steps, false);
	filestailq_clear(&ctx->postponed_files, false);
	free(ctx);
}

static int
_serial_diff(struct rrdp_serial *large, struct rrdp_serial *small, int *result)
{
	BIGNUM *diff;
	BIGNUM *max;
	int error2;
	unsigned long error;
	char errmsg[120];

	error2 = EINVAL;

	diff = BN_create();
	if (!BN_sub(diff, large->num, small->num)) {
		pr_err("%s - %s -> BIGNUM Error:", large->str, small->str);
		while ((error = ERR_get_error()) != 0)
			pr_err("  %s", ERR_error_string(error, errmsg));
		goto diff;
	}

	/* TODO (fine) maybe cache max in the config module */
	max = BN_create();
	if (!BN_set_word(max, RRDP_DELTA_THRESHOLD)) {
		pr_err("BIGNUM assignment (%u) Error:", RRDP_DELTA_THRESHOLD);
		while ((error = ERR_get_error()) != 0)
			pr_err("  %s", ERR_error_string(error, errmsg));
		goto max;
	}

	if (BN_cmp(max, diff) < 0) {
		pr_err("Too many deltas; falling back to Snapshot.");
		goto max;
	}

	*result = BN_get_word(diff);
	error2 = 0;

max:	BN_free(max);
diff:	BN_free(diff);
	return error2;
}

static int
get_serial_diff(struct rrdp_serial *cached, struct update_notification *notif,
    int *result)
{
	int cmp;
	int diff;
	int error;

	cmp = BN_cmp(cached->num, notif->session.serial.num);
	if (cmp < 0) {
		/* Normal situation: The notification has new deltas */
		error = _serial_diff(&notif->session.serial, cached, &diff);
		if (!error)
			*result = diff;

	} else if (cmp > 0) {
		/* The notification is older than what we already have */
		error = _serial_diff(cached, &notif->session.serial, &diff);
		if (!error)
			*result = -diff;

	} else {
		/* The notification and cache have the same serial */
		*result = 0;
		error = 0;
	}

	return error;
}

static struct notification_delta *
find_delta(struct update_notification *notif, int serial_diff, int d)
{
	int index;
	index = d + serial_diff;
	return (index < 0 || notif->deltas.len <= index)
	    ? NULL
	    : &notif->deltas.arr[index];
}

static int
validate_session_desync(struct rrdp_step *step,
    struct update_notification *notif,
    int serial_diff)
{
	struct notification_delta *delta;
	int i;

	for (i = 0; i < RRDP_DELTA_THRESHOLD; i++) {
		if (step == NULL)
			return 0; /* Cache has few deltas */
		/* First step always lacks a hash; there's no delta */
		if (!step->delta_hash.set)
			continue;

		delta = find_delta(notif, serial_diff, i);
		if (!delta)
			continue;
		if (!delta->meta.hash.set)
			continue; /* Probably dead code */

		if (memcmp(step->delta_hash.bytes, delta->meta.hash.bytes, RRDP_HASH_LEN) != 0)
			return pr_err("Notification delta hash for serial %s does not match cached delta hash; "
			    "RRDP session desynchronization detected.",
			    delta->serial.str);

		step = TAILQ_NEXT(step, lh);
	}

	return 0; /* First $delta_threshold delta hashes match */
}

static int
handle_snapshot(struct rrdp_ctx *ctx, struct update_notification *notif)
{
	struct rrdp_steps steps;
	struct rrdp_step *step;
	int error;

	init_steps(&steps, notif);

	step = TAILQ_FIRST(&steps);
	if (!step) {
		step = step_create(&notif->session.serial);
		TAILQ_INSERT_HEAD(&steps, step, lh);
	}

	error = rrdpxml_explode_snapshot(notif, &step->files, &ctx->seq,
	    &ctx->postponed_files);
	if (error) {
		steps_clear(&steps, true);
		return error;
	}

	free(ctx->session_id);
	/* We must not rm the files until the index file has been updated */
	steps_transfer(&ctx->postponed_steps, &ctx->steps);

	ctx->session_id = pstrdup(notif->session.session_id);
	ctx->success = true;
	steps_transfer(&ctx->steps, &steps);

	return 0;
}

static int
handle_delta(struct update_notification *notif,
    struct notification_delta *delta,
    struct rrdp_ctx *ctx)
{
	struct rrdp_step *step;

	step = step_create(&delta->serial);
	step->files = filerefs_clone(&TAILQ_FIRST(&ctx->steps)->files);
	step->delta_hash = delta->meta.hash;
	TAILQ_INSERT_HEAD(&ctx->steps, step, lh);

	return rrdpxml_explode_delta(notif, delta, &step->files, &ctx->seq,
	    &ctx->postponed_files);
}

static int
handle_deltas(struct update_notification *notif, struct rrdp_ctx *ctx,
    int serial_diff)
{
	struct rrdp_serial *old;
	struct rrdp_serial *new;
	int d;
	int error;

	if (notif->deltas.len == 0) {
		pr_trc("There's no delta list to process.");
		return ENOENT;
	}

	old = &TAILQ_FIRST(&ctx->steps)->serial;
	new = &notif->session.serial;

	pr_trc("Handling RRDP delta serials %s-%s.", old->str, new->str);

	if (serial_diff > RRDP_DELTA_THRESHOLD)
		return pr_err("Cached RPP is too old. (Cached serial: %s; current serial: %s)",
		    old->str, new->str);
	if (serial_diff > notif->deltas.len)
		return pr_err("We need %d deltas, but the notification only has %zu.",
		    serial_diff, notif->deltas.len);

	for (d = serial_diff - 1; d >= 0; d--) {
		error = handle_delta(notif, &notif->deltas.arr[d], ctx);
		if (error)
			return error;
	}

	ctx->success = true;
	return 0;
}

/*
 * Downloads the Update Notification @notif_uri, and updates the cache
 * accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into @cage.
 */
int
rrdp_update(struct uri const *notif_uri, char const *cage, time_t mtim,
    bool *changed, struct rrdp_ctx **result)
{
	struct update_notification notif;
	struct rrdp_ctx *ctx;
	struct rrdp_step *step;
	int serial_diff;
	int error;

	fnstack_push(uri_str(notif_uri));

	error = rrdpxml_fetch_notif(notif_uri, mtim, changed, &notif);
	if (error)
		goto pop;
	if (!(*changed)) {
		if (*result)
			(*result)->success = true;
		goto pop;
	}

	pr_trc("New session/serial: %s/%s",
	    notif.session.session_id,
	    notif.session.serial.str);

	if ((*result) == NULL) {
		pr_trc("This is a new Notification.");

		error = file_mkdir(cage, false);
		if (error)
			goto notif;

		ctx = rrdpctx_create();
		cseq_init(&ctx->seq, pstrdup(cage), 0, true);

		error = handle_snapshot(ctx, &notif);
		if (error) {
			file_rm_rf(cage);
			rrdpctx_free(ctx);
			goto notif;
		}

		*result = ctx;
		goto notif;
	}

	ctx = *result;

	if (strcmp(ctx->session_id, notif.session.session_id) != 0) {
		pr_trc("This is a new session.");
		error = handle_snapshot(ctx, &notif);
		goto notif;
	}

	step = TAILQ_FIRST(&ctx->steps);
	if (!step)
		goto snapshot;
	error = get_serial_diff(&step->serial, &notif, &serial_diff);
	if (error)
		goto snapshot;
	error = validate_session_desync(step, &notif, serial_diff);
	if (error)
		goto snapshot;

	if (serial_diff > 0) {
		pr_trc("The Notification's serial changed: %s -> %s",
		    step->serial.str, notif.session.serial.str);

		error = handle_deltas(&notif, ctx, serial_diff);
		if (error) {
snapshot:		pr_trc("Falling back to snapshot.");
			error = handle_snapshot(ctx, &notif);
		}

	} else if (serial_diff < 0) {
		pr_trc("Cached serial is higher than notification serial.");
		ctx->success = true;

	} else {
		pr_trc("The Notification changed, "
		    "but the session ID and serial didn't, "
		    "and no session desync was detected.");
		ctx->success = true;
		*changed = false;
	}

notif:	notification_cleanup(&notif);
pop:	fnstack_pop();
	return error;
}

void
rrdpctx_post_index(struct rrdp_ctx *ctx)
{
	steps_clear(&ctx->postponed_steps, true);
	filestailq_clear(&ctx->postponed_files, true);
}

static void
init_dao_step(struct rrdp_dao *dao)
{
	struct rrdp_step *step;

	TAILQ_FOREACH(step, &dao->ctx->steps, lh)
		/* TODO (fine) when is the hash table empty? */
		/* See twice below at rrdpdao_downgrade_delta(). */
		if (step->files.ht != NULL) {
			dao->step = step;
			return;
		}
}

static void
init_dao_fallback(struct rrdp_dao *dao)
{
	struct fallback *fb;

	fb = fallback_find(&dao->ctx->fbs, &dao->rpkiManifest);
	if (!dao->fb || INTEGER_cmp(&dao->fb->mft.num, &fb->mft.num) < 0) {
		if (dao->fb)
			fallback_free(dao->fb, true);
		dao->fb = fb;
	} else {
		fallback_free(fb, true);
	}
}

struct rrdp_dao *
rrdpdao_create(struct rrdp_ctx *ctx, struct uri const *rpkiManifest)
{
	struct rrdp_dao *result;

	result = pzalloc(sizeof(struct rrdp_dao));
	uri_copy(&result->rpkiManifest, rpkiManifest);
	result->ctx = ctx;
	result->state = RDS_STEP;
	init_dao_step(result);
	init_dao_fallback(result);

	return result;
}

static struct cache_file *
find_file(struct files_ht *ht, struct uri const *url)
{
	struct cache_file_ref *ref;
	ref = filerefs_find_uri(ht, url);
	return ref ? ref->file : NULL;
}

static bool
step_is_fallback(struct rrdp_dao *dao, struct rrdp_step *step)
{
	struct cache_file *step_file, *fb_file;

	if (!dao->fb)
		return false;

	step_file = find_file(&step->files, &dao->rpkiManifest);
	fb_file = find_file(&dao->fb->files, &dao->rpkiManifest);

	if (step_file == fb_file)
		return true;
	if (!step_file || !fb_file)
		return false;
	return strcmp(step_file->map.path, fb_file->map.path) == 0;
}

struct rrdp_serial *
rrdpdao_downgrade_delta(struct rrdp_dao *dao)
{
	struct rrdp_step *step;

	if (!dao)
		return NULL;

	step = dao->step;
	if (!step)
		goto no;

	step = TAILQ_NEXT(step, lh);
	if (step && step->files.ht != NULL)
		goto yes;

no:	pr_trc("There are no more RRDP steps.");
	return NULL;

yes:	if (step_is_fallback(dao, step))
		goto no;

	dao->state = RDS_STEP;
	dao->step = step;
	return &step->serial;
}

bool
rrdpdao_downgrade_fb(struct rrdp_dao *dao)
{
	if (!dao)
		return false;

	if (dao->state == RDS_STEP && dao->fb != NULL) {
		dao->state = RDS_FB;
		return true;
	}

	return false;
}

struct cache_file *
rrdpdao_map(struct rrdp_dao const *querier, struct uri const *url)
{
	struct files_ht *ht = NULL;

	switch (querier->state) {
	case RDS_STEP:
		if (!querier->step)
			return NULL;
		ht = &querier->step->files;
		break;
	case RDS_FB:
		if (!querier->fb)
			return NULL;
		ht = &querier->fb->files;
		break;
	case RDS_DONE:
		return NULL;
	}

	return find_file(ht, url);
}

struct mft_meta const *
rrdpdao_fallback_mftnum(struct rrdp_dao *dao)
{
	return (dao && dao->fb) ? &dao->fb->mft : NULL;
}

void
rrdpdao_commit(struct rrdp_dao *dao, struct rpp *rpp)
{
	pr_trc("Queuing RPP for commit: %s", uri_str(&dao->rpkiManifest));

	switch (dao->state) {
	case RDS_STEP:
		fallback_add(&dao->ctx->fbs, &dao->rpkiManifest, rpp);
		break;
	case RDS_FB:
		pr_trc("It's already a fallback.");
		fallback_commit(&dao->ctx->fbs, dao->fb);
		break;
	case RDS_DONE:
		break;
	}
}

void
rrdpdao_free(struct rrdp_dao *dao)
{
	if (dao) {
		uri_cleanup(&dao->rpkiManifest);
		if (dao->fb)
			fallback_free(dao->fb, true);
		free(dao);
	}
}

static void
cleanup_ctx(struct rrdp_ctx *ctx)
{
	struct rrdp_step *step, *next;
	unsigned int s;

	pr_trc("    Cleaning up session.");

	s = 0;
	TAILQ_FOREACH(step, &ctx->steps, lh) {
		if (s != 0) {
			filerefs_clear(&step->files, true);
			step->files.ht = NULL;
		}
		if (s == (RRDP_DELTA_THRESHOLD - 1u)) {
			while ((next = TAILQ_NEXT(step, lh)) != NULL) {
				TAILQ_REMOVE(&ctx->steps, next, lh);
				step_free(next, true);
			}
		}
		s++;
	}
}

/* Returns whether there's something to salvage. */
bool
rrdpctx_cleanup(struct rrdp_ctx *ctx)
{
	if (!ctx)
		return false;

	pr_trc("    Deleting noncommitted fallbacks.");
	fallbacks_drop_noncommitted(&ctx->fbs);

	/*
	 * I've raised an eyebrow at this logic several times, so better be
	 * verbose:
	 *
	 * Fallbacks make an RRDP context valuable. A fallbackless context is
	 * trash.
	 *
	 * The only reason why we'd want to preserve a trash context is because
	 * it might still be referenced by the RPKI tree, so if we throw it
	 * away, we risk having to re-snapshot in the next cycle.
	 *
	 * BUT THAT ONLY APPLIES IF THE DOWNLOAD WAS SUCCESSFUL. If we have no
	 * fallbacks and tried the snapshot and failed, we'll have to
	 * re-snapshot. If we have no fallbacks and tried a delta THEN snapshot
	 * and still failed, we should re-snapshot anyway.
	 *
	 * Truth table:
	 *
	 * download succeeded, has fallbacks: preserve
	 * download succeeded, lacks fallbacks: preserve
	 * download failed, has fallbacks: preserve, force re-snapshot
	 *    -> If snapshot failed, we'll need re-snapshot.
	 *    -> If delta failed, it'll fail again*1. So re-snapshot.
	 * download failed, lacks fallbacks: throw away
	 * download not attempted, has fallbacks: impossible
	 * download not attempted, lacks fallbacks: throw away
	 *
	 * So "download not attempted" should behave the same as "download
	 * failed."
	 *
	 * *1 This is a bit naive. It'll fail again if the delta was invalid,
	 * but not if it was temporarily unavailable. However, re-snapshotting
	 * is OK in the latter.
	 *
	 * TODO (fine) "download failed" can mean two things: File unreachable
	 * or file unparseable. The former doesn't need to force a re-snapshot.
	 */
	if (ctx->success || !fortcfg.http.enabled) {
		cleanup_ctx(ctx);
		return true;
	} else if (HASH_COUNT(ctx->fbs.ht) > 0) {
		steps_clear(&ctx->steps, true); /* force re-snapshot */
		cleanup_ctx(ctx);
		return true;
	} else {
		pr_trc("    Session is stale and ran out of fallbacks.");
		return false;
	}
}

static int
files2json(json_t *json, struct rrdp_ctx const *ctx)
{
	struct rrdp_step *step;
	struct fallback *fb, *fb2;
	int error;

	TAILQ_FOREACH(step, &ctx->steps, lh)
		filerefs_clear_written(&step->files);
	HASH_ITER(hh, ctx->fbs.ht, fb, fb2)
		filerefs_clear_written(&fb->files);

	TAILQ_FOREACH(step, &ctx->steps, lh) {
		error = filerefs_write(json, &step->files);
		if (error)
			return error;
	}
	HASH_ITER(hh, ctx->fbs.ht, fb, fb2) {
		error = filerefs_write(json, &fb->files);
		if (error)
			return error;
	}

	return 0;
}

static json_t *
step2json(struct rrdp_step *step, bool write_files)
{
	json_t *jstep;

	if (!step->delta_hash.set && !write_files)
		return NULL;

	jstep = json_obj_new();

	if (step->delta_hash.set)
		if (json_add_hash(jstep, "hash", step->delta_hash.bytes))
			goto fail;
	if (write_files)
		if (json_object_add(jstep, "files", filerefs2json(&step->files)))
			goto fail;

	return jstep;

fail:	json_decref(jstep);
	return NULL;
}

json_t *
rrdp_ctx2json(struct rrdp_ctx const *ctx)
{
	json_t *root, *jfiles;
	json_t *jsteps, *jfbs, *jstep;
	struct rrdp_step *step;
	struct fallback *fb, *tmp;
	array_index s;

	if (TAILQ_EMPTY(&ctx->steps) && HASH_COUNT(ctx->fbs.ht) == 0)
		return NULL;

	root = json_obj_new();

	if (json_add_str(root, "session_id", ctx->session_id))
		goto fail;

	jfiles = json_obj_new();
	if (json_object_add(root, "files", jfiles))
		goto fail;
	if (files2json(jfiles, ctx))
		goto fail;

	if (!TAILQ_EMPTY(&ctx->steps)) {
		jsteps = json_obj_new();
		if (json_object_add(root, "steps", jsteps))
			goto fail;
		s = 0;
		TAILQ_FOREACH(step, &ctx->steps, lh) {
			jstep = step2json(step, s == 0);
			if (jstep && json_object_add(jsteps, step->serial.str, jstep))
				goto fail;
			s++;
			if (s >= RRDP_DELTA_THRESHOLD)
				break;
		}
	}

	if (HASH_COUNT(ctx->fbs.ht) > 0) {
		jfbs = json_obj_new();
		if (json_object_add(root, "fallbacks", jfbs))
			goto fail;
		HASH_ITER(hh, ctx->fbs.ht, fb, tmp)
			if (json_object_add(jfbs,
			    uri_str(&fb->rpkiManifest),
			    fallback2json(fb)))
				goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static int
json2step(json_t *json, char const *serial, struct files_ht *files,
    struct rrdp_step **result)
{
	struct rrdp_step *step;
	int error;

	step = pmalloc(sizeof(struct rrdp_step));

	error = str2serial(serial, &step->serial);
	if (error)
		goto step;
	error = json2filerefs(json, "files", files, &step->files);
	if (error < 0)
		goto serial;
	error = json2hash(json, "hash", step->delta_hash.bytes);
	if (error == ENOENT)
		step->delta_hash.set = false;
	else if (error)
		goto files;
	else
		step->delta_hash.set = true;

	*result = step;
	return 0;

files:	filerefs_clear(&step->files, true);
serial:	serial_cleanup(&step->serial);
step:	free(step);
	return error;
}

static int
json2steps(json_t *jsteps, struct rrdp_ctx *ctx, struct files_ht *files)
{
	char const *jkey;
	json_t *child;
	struct rrdp_step *step, *prev;
	BIGNUM *diff;
	array_index s, sn;
	int error;

	prev = NULL;
	diff = BN_create();
	error = 0;

	sn = json_object_size(jsteps);
	if (sn > RRDP_DELTA_THRESHOLD)
		sn = RRDP_DELTA_THRESHOLD;

	s = 0;
	json_object_foreach(jsteps, jkey, child) {
		error = json2step(child, jkey, files, &step);
		if (error)
			break;

		if (prev) {
			if (!BN_sub(diff, prev->serial.num, step->serial.num)) {
				error = pr_err("Cannot compute %s - %s; unknown error.",
				    prev->serial.str, step->serial.str);
				break;
			}
			if (!BN_is_one(diff)) {
				error = pr_err("Serial '%s' is not the successor of '%s'",
				    prev->serial.str, step->serial.str);
				break;
			}
		}

		TAILQ_INSERT_TAIL(&ctx->steps, step, lh);
		prev = step;

		s++;
		if (s >= sn)
			break;
	}

	BN_free(diff);
	return error;
}

/* @path is expected to outlive the context. */
int
rrdp_json2ctx(json_t *json, char *path, struct rrdp_ctx **result)
{
	struct files_ht files;
	json_t *jfiles, *jchild;
	struct rrdp_ctx *ctx;
	char const *str;
	int error;

	error = json_get_object(json, "files", &jfiles);
	if (error)
		return error;
	error = json2files(jfiles, path, &files);
	if (error)
		return error;

	ctx = rrdpctx_create();

	error = json2cseq(&ctx->seq, jfiles, path, false);
	if (error)
		goto fail;

	error = json_get_str(json, "session_id", &str);
	if (error)
		goto fail;
	ctx->session_id = pstrdup(str);

	error = json_get_object(json, "steps", &jchild);
	if (error < 0)
		goto fail;
	if (!error) {
		error = json2steps(jchild, ctx, &files);
		if (error)
			goto fail;
	}

	error = json_get_object(json, "fallbacks", &jchild);
	if (error < 0)
		goto fail;
	if (!error) {
		error = json2fallbacks(jchild, &ctx->fbs, &files);
		if (error)
			goto fail;
	}

	filerefs_clear(&files, true);
	*result = ctx;
	return 0;

fail:	rrdpctx_free(ctx);
	filerefs_clear(&files, true);
	return error;
}

static void
rrdpstep_print(struct rrdp_step *step, int indent)
{
	struct cache_file_ref *ref, *tmp;

	printf("%*s[RRDP Step] serial:%s delta-hash:", indent, "",
	    step->serial.str);
	hash_print(&step->delta_hash);
	printf("\n");

	HASH_ITER(hook.ht, step->files.ht, ref, tmp)
		fileref_print(ref, indent + 2);
}

static void
rrdpsteps_print(struct rrdp_steps *steps, int indent)
{
	struct rrdp_step *step;
	TAILQ_FOREACH(step, steps, lh)
		rrdpstep_print(step, indent);
}

void
rrdpctx_print(struct rrdp_ctx *ctx, int indent)
{
	if (ctx == NULL)
		return;

	printf("%*s[RRDP Context] session_id:%s seq:%lx success:%u\n",
	    indent, "", ctx->session_id, ctx->seq.next_id, ctx->success);
	rrdpsteps_print(&ctx->steps, indent + 2);
	fallbacks_print(&ctx->fbs, indent + 2);
}
