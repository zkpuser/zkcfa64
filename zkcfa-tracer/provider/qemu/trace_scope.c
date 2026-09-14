/* SPDX-License-Identifier: BSD-2-Clause */
/* QEMU linux-user plugin: complete root-entry -> root-return instruction stream. */

#include <qemu/qemu-plugin.h>

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_ROOT_RETURNS 16
#define MAX_INSN_BYTES 16
#define MAX_EXEC_RANGES 8

typedef struct {
	uint64_t pc;
	size_t size;
	uint8_t bytes[MAX_INSN_BYTES];
	bool indirect_jump;
} expected_insn_t;

typedef struct {
	uint64_t raw_pc;
	uint64_t pc;
	bool known;
	bool code_match;
	bool in_target_elf;
	size_t expected_size;
} insn_meta_t;

typedef struct {
	uint64_t call_site;
	uint64_t target;
	uint64_t synthetic;
	uint64_t return_site;
	uint64_t gateway_end;
} external_call_t;

typedef struct {
	uint64_t start;
	uint64_t end;
} exec_range_t;

static FILE *out;
static char elf_sha256[65];
static char architecture[16];
static char trace_schema[32];
static char capture_context[65];
static uint64_t canonical_entry;
static uint64_t canonical_start_code;
static uint64_t runtime_bias;
static bool position_independent;
static bool external_entry;
static uint64_t scope_call;
static uint64_t root_entry;
static uint64_t scope_return;
static uint64_t root_returns[MAX_ROOT_RETURNS];
static size_t root_return_count;
static bool active;
static bool pending_root_entry;
static bool pending_root_return;
static bool wrote_end;
static bool runtime_code_match = true;
static uint64_t count;
static GMutex lock;
static GPtrArray *metadata;
static GHashTable *expected_insns;
static GHashTable *external_calls;
static bool runtime_initialized;
static bool runtime_initialization_failed;
static struct qemu_plugin_register *rsp_handle;
static uint64_t expected_external_return;
static bool expected_external_return_set;
static bool test_force_return_mismatch;
static external_call_t *pending_external_call;
static external_call_t *active_external_call;
static uint64_t external_gateway_next;
/* True only after observing a PC outside every executable primary-ELF PT_LOAD. */
static bool external_departed_target_elf;
static exec_range_t exec_ranges[MAX_EXEC_RANGES];
static size_t exec_range_count;

static uint64_t parse_address(const char *text)
{
	char *end = NULL;
	uint64_t value = strtoull(text, &end, 0);

	if (!text[0] || !end || *end) {
		fprintf(stderr, "[provider-trace] invalid address: %s\n", text);
		exit(EXIT_FAILURE);
	}
	return value;
}

static bool is_root_return(uint64_t pc)
{
	for (size_t i = 0; i < root_return_count; i++)
		if (root_returns[i] == pc)
			return true;
	return false;
}

static bool is_in_target_elf(uint64_t pc)
{
	for (size_t i = 0; i < exec_range_count; i++)
		if (pc >= exec_ranges[i].start && pc < exec_ranges[i].end)
			return true;
	return false;
}

static bool decode_hex(const char *text, uint8_t *bytes, size_t size)
{
	if (strlen(text) != size * 2)
		return false;
	for (size_t i = 0; i < size; i++) {
		int high = g_ascii_xdigit_value(text[i * 2]);
		int low = g_ascii_xdigit_value(text[i * 2 + 1]);

		if (high < 0 || low < 0)
			return false;
		bytes[i] = (uint8_t)((high << 4) | low);
	}
	return true;
}

static bool load_map(const char *path)
{
	char line[512];
	FILE *stream = fopen(path, "r");

	if (!stream || !fgets(line, sizeof(line), stream) ||
	    strcmp(g_strchomp(line), "zkcfa.provider.map")) {
		if (stream)
			fclose(stream);
		return false;
	}
	while (fgets(line, sizeof(line), stream)) {
		unsigned long long pc;
		unsigned long long block;
		unsigned long long target;
		unsigned int size;
		char insn_kind[32];
		char encoding[MAX_INSN_BYTES * 2 + 1];
		char kind[32] = { 0 };
		char value[160] = { 0 };
		int fields = sscanf(line, "%31s %159s", kind, value);

		if (g_str_has_prefix(line, "insn ")) {
			expected_insn_t *entry;
			uint64_t *key;

			if (sscanf(line, "insn %llx %u %llx %31s %llx %32s",
				   &pc, &size, &block, insn_kind, &target, encoding) != 6)
				goto bad;
			(void)block;
			(void)target;
			(void)insn_kind;
			if (!size || size > MAX_INSN_BYTES ||
			    g_hash_table_contains(expected_insns, &pc))
				goto bad;
			entry = g_new0(expected_insn_t, 1);
			key = g_new(uint64_t, 1);
			entry->pc = pc;
			entry->size = size;
			entry->indirect_jump = !strcmp(insn_kind, "indirect_jump");
			*key = pc;
			if (!decode_hex(encoding, entry->bytes, size)) {
				g_free(entry);
				g_free(key);
				goto bad;
			}
			g_hash_table_insert(expected_insns, key, entry);
			continue;
		}
		if (g_str_has_prefix(line, "external_call ")) {
			external_call_t *entry;
			uint64_t *key;
			unsigned long long call_site;
			unsigned long long external_target;
			unsigned long long synthetic;
			unsigned long long return_site;
			unsigned long long gateway_end;
			char symbol[160];

			if (sscanf(line, "external_call %llx %llx %llx %llx %llx %159s",
				   &call_site, &external_target, &synthetic,
				   &return_site, &gateway_end, symbol) != 6 ||
			    gateway_end <= external_target ||
			    g_hash_table_contains(external_calls, &call_site))
				goto bad;
			entry = g_new0(external_call_t, 1);
			key = g_new(uint64_t, 1);
			entry->call_site = call_site;
			entry->target = external_target;
			entry->synthetic = synthetic;
			entry->return_site = return_site;
			entry->gateway_end = gateway_end;
			*key = call_site;
			g_hash_table_insert(external_calls, key, entry);
			continue;
		}
		if (g_str_has_prefix(line, "exec_range ")) {
			unsigned long long start;
			unsigned long long end;

			if (sscanf(line, "exec_range %llx %llx", &start, &end) != 2 ||
			    start >= end || exec_range_count >= MAX_EXEC_RANGES)
				goto bad;
			exec_ranges[exec_range_count].start = start;
			exec_ranges[exec_range_count].end = end;
			exec_range_count++;
			continue;
		}

		if (fields != 2)
			continue;
		if (!strcmp(kind, "elf_sha256")) {
			if (strlen(value) != 64)
				goto bad;
			for (size_t i = 0; i < 64; i++)
				if (g_ascii_xdigit_value(value[i]) < 0)
					goto bad;
			memcpy(elf_sha256, value, 65);
		} else if (!strcmp(kind, "trace_schema")) {
			if (strcmp(value, "zkcfa.scope.trace"))
				goto bad;
			strcpy(trace_schema, value);
		} else if (!strcmp(kind, "scope_call")) {
			scope_call = parse_address(value);
		} else if (!strcmp(kind, "architecture")) {
			if (strlen(value) >= sizeof(architecture))
				goto bad;
			strcpy(architecture, value);
		} else if (!strcmp(kind, "canonical_entry")) {
			canonical_entry = parse_address(value);
		} else if (!strcmp(kind, "canonical_start_code")) {
			canonical_start_code = parse_address(value);
		} else if (!strcmp(kind, "position_independent")) {
			if (strcmp(value, "0") && strcmp(value, "1"))
				goto bad;
			position_independent = !strcmp(value, "1");
		} else if (!strcmp(kind, "boundary_mode")) {
			if (!strcmp(value, "external_entry"))
				external_entry = true;
			else if (strcmp(value, "direct_call"))
				goto bad;
		} else if (!strcmp(kind, "root_entry")) {
			root_entry = parse_address(value);
		} else if (!strcmp(kind, "scope_return")) {
			scope_return = parse_address(value);
		} else if (!strcmp(kind, "root_ret")) {
			if (root_return_count >= MAX_ROOT_RETURNS)
				goto bad;
			root_returns[root_return_count++] = parse_address(value);
		}
	}
	fclose(stream);
	if (!(elf_sha256[0] && architecture[0] && trace_schema[0] && root_entry && scope_return && root_return_count &&
	      (external_entry || (scope_call && g_hash_table_contains(expected_insns, &scope_call))) &&
	      g_hash_table_contains(expected_insns, &root_entry)))
		return false;
	if (position_independent && (!canonical_entry || !canonical_start_code))
		return false;
	if (g_hash_table_size(external_calls) > 0 && !exec_range_count)
		return false;
	if (g_hash_table_size(external_calls) > 0) {
		GHashTableIter iterator;
		gpointer key;
		gpointer value;

		g_hash_table_iter_init(&iterator, external_calls);
		while (g_hash_table_iter_next(&iterator, &key, &value)) {
			external_call_t *call = value;
			expected_insn_t *gateway_exit = NULL;
			GHashTableIter instruction_iterator;
			gpointer instruction_key;
			gpointer instruction_value;

			(void)key;
			if (!is_in_target_elf(call->call_site) ||
			    !is_in_target_elf(call->target) ||
			    !is_in_target_elf(call->gateway_end - 1) ||
			    !is_in_target_elf(call->return_site) ||
			    !g_hash_table_contains(expected_insns, &call->call_site) ||
			    !g_hash_table_contains(expected_insns, &call->target) ||
			    !g_hash_table_contains(expected_insns, &call->return_site))
				return false;
			g_hash_table_iter_init(&instruction_iterator, expected_insns);
			while (g_hash_table_iter_next(&instruction_iterator,
						     &instruction_key, &instruction_value)) {
				expected_insn_t *instruction = instruction_value;

				(void)instruction_key;
				if (instruction->pc >= call->target &&
				    instruction->pc + instruction->size == call->gateway_end) {
					if (gateway_exit)
						return false;
					gateway_exit = instruction;
				}
			}
			if (!gateway_exit || !gateway_exit->indirect_jump)
				return false;
		}
	}
	for (size_t i = 0; i < root_return_count; i++)
		if (!g_hash_table_contains(expected_insns, &root_returns[i]))
			return false;
	return true;
bad:
	fclose(stream);
	return false;
}

static bool verify_target_measurement(void)
{
	char *path = (char *)qemu_plugin_path_to_binary();
	gchar *contents = NULL;
	gsize length = 0;
	gchar *digest;
	bool matches;

	if (!path || !g_file_get_contents(path, &contents, &length, NULL)) {
		g_free(path);
		return false;
	}
	digest = g_compute_checksum_for_data(
		G_CHECKSUM_SHA256, (const guchar *)contents, length);
	matches = digest && !strcmp(digest, elf_sha256);
	g_free(digest);
	g_free(contents);
	g_free(path);
	return matches;
}

static uint64_t decode_u64_le(const uint8_t *bytes)
{
	uint64_t value = 0;

	for (size_t i = 0; i < sizeof(value); i++)
		value |= (uint64_t)bytes[i] << (8 * i);
	return value;
}

static bool capture_external_return(void)
{
	GByteArray *reg = g_byte_array_new();
	GByteArray *memory = g_byte_array_new();
	uint64_t rsp;
	bool ok = false;

	if (!rsp_handle || qemu_plugin_read_register(rsp_handle, reg) < 8)
		goto done;
	rsp = decode_u64_le(reg->data);
	if (!qemu_plugin_read_memory_vaddr(rsp, memory, 8) || memory->len < 8)
		goto done;
	expected_external_return = decode_u64_le(memory->data);
	if (test_force_return_mismatch)
		expected_external_return ^= 1;
	expected_external_return_set = expected_external_return != 0;
	ok = expected_external_return_set;
done:
	g_byte_array_free(memory, TRUE);
	g_byte_array_free(reg, TRUE);
	return ok;
}

static void finish_trace(bool complete)
{
	if (wrote_end)
		return;
	fprintf(out, "end count=%" PRIu64 " complete=%u runtime_code_match=%u\n",
		count, complete ? 1U : 0U, runtime_code_match ? 1U : 0U);
	fflush(out);
	wrote_end = true;
}

static void execute(unsigned int cpu_index, void *userdata)
{
	insn_meta_t *meta = userdata;
	uint64_t pc = meta->pc;

	(void)cpu_index;
	g_mutex_lock(&lock);
	if (cpu_index != 0 && (active || pending_external_call || active_external_call)) {
		fprintf(out, "boundary_error unsupported_vcpu=%u\n", cpu_index);
		active = false;
		finish_trace(false);
		g_mutex_unlock(&lock);
		return;
	}
	if (pending_external_call) {
		if (pc != pending_external_call->target || !meta->known || !meta->code_match) {
			runtime_code_match = runtime_code_match && meta->known && meta->code_match;
			fprintf(out, "boundary_error external_target_expected=0x%" PRIx64
				" observed=0x%" PRIx64 "\n",
				pending_external_call->target, pc);
			pending_external_call = NULL;
			active = false;
			finish_trace(false);
			g_mutex_unlock(&lock);
			return;
		}
		fprintf(out, "external_call after_count=%" PRIu64
			" call_site=0x%" PRIx64 " target=0x%" PRIx64
			" synthetic=0x%" PRIx64 " return=0x%" PRIx64 "\n",
			count, pending_external_call->call_site,
			pending_external_call->target, pending_external_call->synthetic,
			pending_external_call->return_site);
		active_external_call = pending_external_call;
		external_gateway_next = pc + meta->expected_size;
		external_departed_target_elf = false;
		pending_external_call = NULL;
		fflush(out);
		g_mutex_unlock(&lock);
		return;
	}
	if (active_external_call) {
		if (pc == active_external_call->return_site) {
			if (!external_departed_target_elf ||
			    !meta->known || !meta->code_match) {
				runtime_code_match = runtime_code_match && meta->known && meta->code_match;
				fprintf(out, "boundary_error external_return_invalid=0x%" PRIx64 "\n", pc);
				active_external_call = NULL;
				active = false;
				finish_trace(false);
				g_mutex_unlock(&lock);
				return;
			}
		} else if (pc == external_gateway_next && pc < active_external_call->gateway_end) {
			if (!meta->known || !meta->code_match) {
				runtime_code_match = runtime_code_match && meta->known && meta->code_match;
				fprintf(out, "boundary_error external_gateway_code_mismatch=0x%" PRIx64 "\n", pc);
				active_external_call = NULL;
				active = false;
				finish_trace(false);
				g_mutex_unlock(&lock);
				return;
			}
			external_gateway_next = pc + meta->expected_size;
			g_mutex_unlock(&lock);
			return;
		} else {
			if (meta->in_target_elf) {
				fprintf(out, "boundary_error external_reentry_expected=0x%" PRIx64
					" observed=0x%" PRIx64 "\n",
					active_external_call->return_site, pc);
				active_external_call = NULL;
				active = false;
				finish_trace(false);
			} else if (!external_departed_target_elf) {
				if (external_gateway_next != active_external_call->gateway_end) {
					fprintf(out, "boundary_error external_gateway_early_exit=0x%" PRIx64 "\n", pc);
					active_external_call = NULL;
					active = false;
					finish_trace(false);
				} else {
					external_departed_target_elf = true;
				}
			}
			g_mutex_unlock(&lock);
			return;
		}
		fprintf(out, "external_return after_count=%" PRIu64
			" synthetic=0x%" PRIx64 " return=0x%" PRIx64 "\n",
			count, active_external_call->synthetic,
			active_external_call->return_site);
		active_external_call = NULL;
	}
	if (pending_root_return) {
		if ((external_entry && expected_external_return_set &&
		     meta->raw_pc == expected_external_return) ||
		    (!external_entry && pc == scope_return)) {
			fprintf(out, "scope_exit 0x%" PRIx64
				" return_continuation_matched=1\n",
				external_entry ? scope_return : pc);
			active = false;
			pending_root_return = false;
			finish_trace(true);
			g_mutex_unlock(&lock);
			return;
		}
		fprintf(out, "boundary_error expected=0x%" PRIx64
			" observed=0x%" PRIx64 "\n", scope_return, pc);
		active = false;
		pending_root_return = false;
		finish_trace(false);
		g_mutex_unlock(&lock);
		return;
	}
	if (external_entry && !active && !wrote_end && pc == root_entry) {
		if (!meta->known || !meta->code_match) {
			runtime_code_match = false;
			fprintf(out, "boundary_error runtime_root_%s pc=0x%" PRIx64 "\n",
				meta->known ? "mismatch" : "unknown", pc);
			finish_trace(false);
			g_mutex_unlock(&lock);
			return;
		}
		if (!capture_external_return()) {
			fprintf(out, "boundary_error cannot_capture_external_return\n");
			finish_trace(false);
			g_mutex_unlock(&lock);
			return;
		}
		active = true;
		count = 0;
		fprintf(out, "begin scope_call=0x%" PRIx64 " root=0x%" PRIx64
			" scope_return=0x%" PRIx64
			" boundary_kind=external-root-entry-and-captured-return\n",
			scope_call, root_entry, scope_return);
	}
	if (pending_root_entry) {
		pending_root_entry = false;
		if (pc != root_entry || !meta->known || !meta->code_match) {
			runtime_code_match = runtime_code_match && meta->known && meta->code_match;
			fprintf(out, "boundary_error expected_root=0x%" PRIx64
				" observed=0x%" PRIx64 "\n", root_entry, pc);
			finish_trace(false);
			g_mutex_unlock(&lock);
			return;
		}
		active = true;
		count = 0;
		fprintf(out, "begin scope_call=0x%" PRIx64 " root=0x%" PRIx64
			" scope_return=0x%" PRIx64
			" boundary_kind=in-binary-direct-call-and-root-ret\n",
			scope_call, root_entry, scope_return);
	}
	if (!active && !wrote_end && pc == scope_call) {
		if (!meta->known || !meta->code_match) {
			runtime_code_match = false;
			fprintf(out, "boundary_error runtime_code_%s pc=0x%" PRIx64 "\n",
				meta->known ? "mismatch" : "unknown", pc);
			finish_trace(false);
		} else {
			pending_root_entry = true;
		}
		g_mutex_unlock(&lock);
		return;
	}
	if (!active && !wrote_end && pc == root_entry) {
		fprintf(out, "boundary_error root_entered_without_scope_call pc=0x%" PRIx64 "\n", pc);
		finish_trace(false);
		g_mutex_unlock(&lock);
		return;
	}
	if (active &&
	    (!meta->known || !meta->code_match)) {
		runtime_code_match = false;
		fprintf(out, "boundary_error runtime_code_%s pc=0x%" PRIx64 "\n",
			meta->known ? "mismatch" : "unknown", pc);
		active = false;
		finish_trace(false);
		g_mutex_unlock(&lock);
		return;
	}
	if (active) {
		external_call_t *external;

		fprintf(out, "insn %" PRIu64 " 0x%" PRIx64 "\n", count++, pc);
		pending_root_return = is_root_return(pc);
		external = g_hash_table_lookup(external_calls, &pc);
		if (external)
			pending_external_call = external;
	}
	/*
	 * Do not flush once per instruction.  finish_trace(), external-call entry,
	 * initialization, and fclose() at plugin exit publish buffered events at
	 * explicit boundaries.  Per-event flushing dominates long traces without
	 * changing their byte stream.
	 */
	g_mutex_unlock(&lock);
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	(void)id;
	g_mutex_lock(&lock);
	if (!runtime_initialized && !runtime_initialization_failed) {
		if (!verify_target_measurement()) {
			runtime_initialization_failed = true;
			fprintf(out, "boundary_error target_measurement_mismatch\n");
			finish_trace(false);
		} else if (position_independent) {
			uint64_t runtime_start_code = qemu_plugin_start_code();

			if (runtime_start_code < canonical_start_code) {
				runtime_initialization_failed = true;
				fprintf(out, "boundary_error invalid_pie_start_mapping\n");
				finish_trace(false);
			} else {
				runtime_bias = runtime_start_code - canonical_start_code;
			}
		}
		if (!runtime_initialization_failed) {
			runtime_initialized = true;
			fprintf(out, "%s elf_sha256=%s runtime_bias=0x%" PRIx64,
				trace_schema, elf_sha256, runtime_bias);
			if (capture_context[0])
				fprintf(out, " capture_context=%s", capture_context);
			fputc('\n', out);
			fflush(out);
		}
	}
	if (!runtime_initialized) {
		g_mutex_unlock(&lock);
		return;
	}
	g_mutex_unlock(&lock);
	for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		insn_meta_t *meta = g_new0(insn_meta_t, 1);
		expected_insn_t *expected;
		uint8_t bytes[MAX_INSN_BYTES];
		size_t size;

		meta->raw_pc = qemu_plugin_insn_vaddr(insn);
		meta->pc = meta->raw_pc;
		if (position_independent) {
			if (meta->pc < runtime_bias) {
				meta->pc = 0;
			} else {
				meta->pc -= runtime_bias;
			}
		}
		meta->in_target_elf = is_in_target_elf(meta->pc);
		expected = g_hash_table_lookup(expected_insns, &meta->pc);
		if (expected) {
			meta->known = true;
			meta->expected_size = expected->size;
			size = qemu_plugin_insn_size(insn);
			meta->code_match =
				size == expected->size && size <= sizeof(bytes) &&
				qemu_plugin_insn_data(insn, bytes, size) == size &&
				!memcmp(bytes, expected->bytes, size);
		}
		g_ptr_array_add(metadata, meta);
		qemu_plugin_register_vcpu_insn_exec_cb(
			insn, execute,
			external_entry && meta->pc == root_entry
				? QEMU_PLUGIN_CB_R_REGS : QEMU_PLUGIN_CB_NO_REGS,
			meta);
	}
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int cpu_index)
{
	GArray *registers;

	(void)id;
	if (cpu_index != 0)
		return;
	registers = qemu_plugin_get_registers();
	for (size_t i = 0; i < registers->len; i++) {
		qemu_plugin_reg_descriptor *descriptor = &g_array_index(
			registers, qemu_plugin_reg_descriptor, i);

		if (!g_ascii_strcasecmp(descriptor->name, "rsp")) {
			rsp_handle = descriptor->handle;
			break;
		}
	}
	g_array_free(registers, TRUE);
}

static void at_exit(qemu_plugin_id_t id, void *userdata)
{
	(void)id;
	(void)userdata;
	g_mutex_lock(&lock);
	if (!wrote_end)
		finish_trace(false);
	if (out) {
		fclose(out);
		out = NULL;
	}
	if (metadata) {
		g_ptr_array_free(metadata, TRUE);
		metadata = NULL;
	}
	if (expected_insns) {
		g_hash_table_destroy(expected_insns);
		expected_insns = NULL;
	}
	if (external_calls) {
		g_hash_table_destroy(external_calls);
		external_calls = NULL;
	}
	g_mutex_unlock(&lock);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
					   const qemu_info_t *info,
					   int argc, char **argv)
{
	const char *map_path = NULL;
	const char *log_path = NULL;
	const char *capture_context_arg = NULL;

	(void)info;
	for (int i = 0; i < argc; i++) {
		if (g_str_has_prefix(argv[i], "map="))
			map_path = argv[i] + 4;
		else if (g_str_has_prefix(argv[i], "log="))
			log_path = argv[i] + 4;
		else if (g_str_has_prefix(argv[i], "capture-context="))
			capture_context_arg = argv[i] + strlen("capture-context=");
		else if (!strcmp(argv[i], "test-force-return-mismatch=1"))
			test_force_return_mismatch = true;
	}
	if (capture_context_arg && (strlen(capture_context_arg) != 64 ||
	    strspn(capture_context_arg, "0123456789abcdef") != 64)) {
		fprintf(stderr, "[provider-trace] invalid capture-context\n");
		return -1;
	}
	if (capture_context_arg)
		strcpy(capture_context, capture_context_arg);
	expected_insns = g_hash_table_new_full(
		g_int64_hash, g_int64_equal, g_free, g_free);
	external_calls = g_hash_table_new_full(
		g_int64_hash, g_int64_equal, g_free, g_free);
	if (!map_path || !log_path || !load_map(map_path)) {
		fprintf(stderr, "[provider-trace] require valid map= and log=\n");
		g_hash_table_destroy(expected_insns);
		expected_insns = NULL;
		g_hash_table_destroy(external_calls);
		external_calls = NULL;
		return -1;
	}
	out = fopen(log_path, "w");
	if (!out) {
		g_hash_table_destroy(expected_insns);
		expected_insns = NULL;
		g_hash_table_destroy(external_calls);
		external_calls = NULL;
		return -1;
	}
	metadata = g_ptr_array_new_with_free_func(g_free);
	qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
	qemu_plugin_register_atexit_cb(id, at_exit, NULL);
	return 0;
}
