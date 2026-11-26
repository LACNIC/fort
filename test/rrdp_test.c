#include <check.h>

#include "alloc.c"
#include "asn1/asn1c/INTEGER.c"
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/asn_internal.c"
#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/constraints.c"
#include "asn1/asn1c/der_encoder.c"
#include "base64.c"
#include "cachefile.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "hash.c"
#include "mock.c"
#include "rrdp.c"
#include "rrdp_xml.c"
#include "types/uri.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"

__MOCK_ABORT(http_download, int, 0, struct uri const *u, curl_write_callback cb,
    void *a, curl_off_t i, bool *ch)

/* Converts @src into JSON forth and back. Checks the result equals @src. */
static void
ck_json(struct rrdp_ctx const *src)
{
	struct rrdp_ctx *dst;
	json_t *json;

	json = rrdp_ctx2json(src);
	json_dumpf(json, stdout, JSON_INDENT(2));
	printf("\n");
	ck_assert_ptr_ne(NULL, json);
	ck_assert_int_eq(0, rrdp_json2ctx(json, src->seq.pfx.str, &dst));
	json_decref(json);

	/* FIXME (test) not checking sessions */
	ck_assert_str_eq(src->seq.pfx.str, dst->seq.pfx.str);
	ck_assert_int_eq(src->seq.next_id, dst->seq.next_id);

	rrdpctx_free(dst);
}

struct cache_file *
_cachefile_create(char const *uri, char *path, int hashchr)
{
	struct uri _uri;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	__URI_INIT(&_uri, uri);
	memset(hash, hashchr, SHA256_DIGEST_LENGTH);

	return cachefile_create(&_uri, path, strrchr(path, '/') + 1, hash);
}

static void
step_add_fileref(struct rrdp_step *step, struct cache_file *file)
{
	struct cache_file_ref *fileref;
	char const *urlstr;
	size_t urlen;

	fileref = fileref_create(file);
	urlstr = uri_str(&fileref->file->map.url);
	urlen = uri_len(&fileref->file->map.url);
	HASH_ADD_KEYPTR(hook.ht, step->files.ht, urlstr, urlen, fileref);
}

static void
add_step(struct rrdp_ctx *ctx, char const *serial, int hashchr, ...)
{
	struct rrdp_step *step;
	va_list ap;
	struct cache_file *file;

	step = pzalloc(sizeof(struct rrdp_step));
	TAILQ_INSERT_TAIL(&ctx->steps, step, lh);

	ck_assert_int_eq(0, str2serial(serial, &step->serial));

	va_start(ap, hashchr);
	while ((file = va_arg(ap, struct cache_file *)) != NULL)
		step_add_fileref(step, file);
	va_end(ap);

	memset(step->delta_hash.bytes, hashchr, RRDP_HASH_LEN);
	step->delta_hash.set = true;
}

START_TEST(test_json)
{
	/* TODO (fine) no cleanup */

	struct rrdp_ctx ctx;
	struct cache_file *f1, *f2, *f3, *f4;

	f1 = _cachefile_create("https://n/a.cer", "https/22/0", 0x0a);
	f2 = _cachefile_create("https://n/b.cer", "https/22/1", 0x0b);
	f3 = _cachefile_create("https://n/c.cer", "https/22/2", 0x0c);
	f4 = _cachefile_create("https://n/d.cer", "https/22/3", 0x0d);

	ctx.session_id = "session1";
	TAILQ_INIT(&ctx.steps);
	add_step(&ctx, "3", 0x03, f1, f4, NULL);
	add_step(&ctx, "2", 0x02, f2, f3, f4, NULL);
	add_step(&ctx, "1", 0x01, f1, f2, f3, NULL);
	ctx.success = false;
	ctx.fbs.ht = NULL;
	ck_assert_int_eq(0, pthread_mutex_init(&ctx.fbs.lock, NULL));
	cseq_init(&ctx.seq, "http/22", 4, false);

	ck_json(&ctx);
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *json;

	json = tcase_create("json");
	tcase_add_test(json, test_json);

	suite = suite_create("RRDP");
	suite_add_tcase(suite, json);

	return suite;
}

int
main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	fortcfg.http.max_file_size = 10000;

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
