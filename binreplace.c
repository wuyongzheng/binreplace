/* wish list
 * use native io instead of stdio for performance
 * optimize immortal_alloc
 * simplify replace_file */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

/* It's either windows or POSIX */
#if defined(_MSC_VER) || defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
# define BR_WINDOWS
# include <windows.h>
#else
# define BR_POSIX
# include <sys/stat.h>
# include <unistd.h>
# include <errno.h>
#endif

#define DEFAULT_BUFSIZE      (1024*1024)

struct file_struct {
	char *path;
	struct file_struct *next;
};

/* prefix tree node.
 * a leaf is always a terminate, but not vice versa. */
struct pretree_node {
	struct pretree_node *next; // sibling
	struct pretree_node *child; // head of children
	unsigned char *prefix; // never null
	unsigned char *newstr; // null means it's not a terminate.
	int prefix_len; // > 0
	int oldstr_len; // > 0. oldstr_len is the length of the full search string.
	int newstr_len; // >= 0
};

static int silent_dup = 0;
static int longest_oldstr = 0;
static int inbuff_size = DEFAULT_BUFSIZE;
static unsigned char *inbuff = NULL;

static struct pretree_node *pretree_roots[256] = {NULL};

#define FATAL_ERROR(...) do{fprintf(stderr, __VA_ARGS__);exit(1);}while(0)

/* result must have at least strlen(exp)+1 space
 * return length of result. */
static int unescape (unsigned char *result, const char *exp)
{
	int result_len = 0;
	while (*exp) {
		if (*exp != '\\') {
			result[result_len ++] = *(exp ++);
			continue;
		}
		exp ++;
		switch (*exp) {
		case 'n':
			result[result_len ++] = '\n';
			exp ++;
			break;
		case 'r':
			result[result_len ++] = '\r';
			exp ++;
			break;
		case 't':
			result[result_len ++] = '\t';
			exp ++;
			break;
		case '\\':
			result[result_len ++] = '\\';
			exp ++;
			break;
		case 'x': {
				int num1, num2;

				if (*(exp+1) >= '0' && *(exp+1) <= '9')
					num1 = *(exp+1) - '0';
				else if (*(exp+1) >= 'a' && *(exp+1) <= 'f')
					num1 = 10 + *(exp+1) - 'a';
				else if (*(exp+1) >= 'A' && *(exp+1) <= 'F')
					num1 = 10 + *(exp+1) - 'A';
				else
					FATAL_ERROR("expect \\xff, but '%c' found\n", *(exp+1));

				if (*(exp+2) >= '0' && *(exp+2) <= '9')
					num2 = *(exp+2) - '0';
				else if (*(exp+2) >= 'a' && *(exp+2) <= 'f')
					num2 = 10 + *(exp+2) - 'a';
				else if (*(exp+2) >= 'A' && *(exp+2) <= 'F')
					num2 = 10 + *(exp+2) - 'A';
				else
					FATAL_ERROR("expect \\xff, but '%c' found\n", *(exp+2));

				result[result_len ++] = (char)(num1*16 + num2);
				exp += 3;
			}
			break;
		case '0':
			result[result_len ++] = '\0';
			exp ++;
			break;
		case '\0':
			FATAL_ERROR("unexpected end of escape sequence\n");
		default:
			FATAL_ERROR("unrecognized \\%c escape sequence\n", *exp);
		}
	}
	return result_len;
}

/* result length is exactly strlen(exp)/2 */
static void unhex (unsigned char *result, const char *exp)
{
	int count = 0;
	while (1) {
		char c;
		int i;

		if ((c = exp[count ++]) == '\0')
			break;
		if ('0' <= c && c <= '9') i = (c - '0') * 16;
		else if ('a' <= c && c <= 'f') i = (c - 'a' + 10) * 16;
		else if ('A' <= c && c <= 'F') i = (c - 'A' + 10) * 16;
		else FATAL_ERROR("invalid hex string: %s\n", exp);
		if ((c = exp[count ++]) == '\0')
			break;
		if ('0' <= c && c <= '9') i += c - '0';
		else if ('a' <= c && c <= 'f') i += c - 'a' + 10;
		else if ('A' <= c && c <= 'F') i += c - 'A' + 10;
		else FATAL_ERROR("invalid hex string: %s\n", exp);
		result[count/2-1] = (unsigned char)i;
	}
}

static void print_escape (FILE *fp, const unsigned char *str, int length)
{
	while (length > 0) {
		if (*str >= ' ' && *str <= '~')
			fputc(*str, fp);
		else if (*str == '\n')
			fputs("\\n", fp);
		else if (*str == '\r')
			fputs("\\r", fp);
		else if (*str == '\t')
			fputs("\\t", fp);
		else if (*str == '\\')
			fputs("\\\\", fp);
		else if (*str == '\0')
			fputs("\\0", fp);
		else
			fprintf(fp, "\\x%02x", *str);

		str ++;
		length --;
	}
}

/* immortal_alloc: allocates memory which can't be freed.
 * It is good for allocating small-sized memory, because it wastes less memory.
 * This function can be easily reused. */
/* POOL_NUM: number of pools to keep.
 * The larger POOL_NUM, the smaller wasted boundry space,
 * but the slower (because of sequential search) allocation speed. */
#define IMMORTAL_ALLOC_POOL_NUM 4
/* POOL_SIZE(n): the size of n-th pool. n starts from 1. */
#define IMMORTAL_ALLOC_POOL_SIZE(n) ((n) * 4096)
/* When an allocation of size k can't fit in any pool,
 * a new pool is created if k < MAX_TRIGER.
 * a dedicated malloc is used if k >= MAX_TRIGER.
 * If MAX_TRIGER is too large, new pool gets created too early.
 * If MAX_TRIGER is too small, too many dedicated malloc is called. */
#define IMMORTAL_ALLOC_MAX_TRIGER 1024
static unsigned char *immortal_alloc (int size, int alignment, const unsigned char *init_value)
{
	static unsigned char *pool_ptr[IMMORTAL_ALLOC_POOL_NUM];
	static int pool_size[IMMORTAL_ALLOC_POOL_NUM] = {0};
	static int num_pool_created = 0;
	int count;
	int best_pool;
	int best_pool_size;
	int best_pool_gap;
	unsigned char *retval;

	assert(size > 0);

	/* step 1. find the _best_ pool to store it.
	   hard to describe _best_, read the code. */
	best_pool = -1;
	best_pool_size = 0x77777777;
	if (!alignment) {
		best_pool_gap = 0;
		for (count = 0; count < IMMORTAL_ALLOC_POOL_NUM; count ++) {
			if (pool_size[count] >= size &&
					pool_size[count] < best_pool_size) {
				best_pool = count;
				best_pool_size = pool_size[count];
			}
		}
	} else {
		best_pool_gap = sizeof(void *);
		for (count = 0; count < IMMORTAL_ALLOC_POOL_NUM; count ++) {
			int gap = (int)(0 - (unsigned long)pool_ptr[count]) & (sizeof(void *) - 1);

			if (pool_size[count] < size + gap)
				continue;

			if (gap < best_pool_gap) {
				best_pool = count;
				best_pool_size = pool_size[count];
				best_pool_gap = gap;
			} else if (gap == best_pool_gap && pool_size[count] < best_pool_size) {
				best_pool = count;
				best_pool_size = pool_size[count];
			}
		}
		//TODO: if there is gap, and poolnum < IMMORTAL_ALLOC_POOL_NUM, maybe should create new pool?
	}

	/* step 2. if no pool found, create a pool, or make a dedicated allocation */
	if (best_pool == -1) {
		int next_pool_size = IMMORTAL_ALLOC_POOL_SIZE(num_pool_created + 1);

		/* make a dedicated allocation */
		if (size >= IMMORTAL_ALLOC_MAX_TRIGER) {
			retval = (unsigned char *)malloc(size);
			if (retval == NULL)
				return NULL;
			goto out;
		}

		/* find the smallest pool */
		best_pool = -1;
		best_pool_size = 0x7fffffff;
		for (count = 0; count < IMMORTAL_ALLOC_POOL_NUM; count ++) {
			if (pool_size[count] < best_pool_size) {
				best_pool = count;
				best_pool_size = pool_size[count];
			}
		}

		pool_ptr[best_pool] = (unsigned char *)malloc(next_pool_size);
		if (pool_ptr[best_pool] == NULL)
			return NULL;
		pool_size[best_pool] = next_pool_size;
		best_pool_size = next_pool_size;
		best_pool_gap = (int)(0 - (unsigned long)pool_ptr[best_pool]) & (sizeof(void *) - 1);
		num_pool_created ++;
	}

	/* step 3: now we have a pool. allocate the thing in the pool */
	retval = pool_ptr[best_pool] + best_pool_gap;
	pool_ptr[best_pool] += size + best_pool_gap;
	pool_size[best_pool] -= size + best_pool_gap;

out:
	if (init_value != NULL)
		memcpy(retval, init_value, size);

	//fprintf(stderr, "immortal_alloc -> %p (alignment=%d, size=%d, gap=%d)\n", retval, alignment, size, best_pool_gap);
	return retval;
}

static struct pretree_node *pretree_search (const unsigned char *str)
{
	struct pretree_node *curr;
	struct pretree_node *last_match = NULL;

	curr = pretree_roots[*str];
	while (curr != NULL) {
		if (memcmp(str, curr->prefix, curr->prefix_len) != 0)
			break;
		if (curr->newstr != NULL)
			last_match = curr;
		str += curr->prefix_len;
		for (curr = curr->child; curr != NULL; curr = curr->next)
			if (curr->prefix[0] == *str)
				break;
	}
	return last_match;
}

static struct pretree_node *pretree_search_len (
		const unsigned char *str,
		int length)
{
	struct pretree_node *curr;
	struct pretree_node *last_match = NULL;

	curr = pretree_roots[*str];
	while (curr != NULL) {
		if (length < curr->prefix_len ||
				memcmp(str, curr->prefix, curr->prefix_len) != 0)
			break;
		if (curr->newstr != NULL)
			last_match = curr;
		str += curr->prefix_len;
		length -= curr->prefix_len;
		if (length <= 0) // this step can be ommited if we are allowed to read str[length].
			break;
		for (curr = curr->child; curr != NULL; curr = curr->next)
			if (curr->prefix[0] == *str)
				break;
	};
	return last_match;
}

#ifdef DEBUG
static void pretree_dump_rec (struct pretree_node *curr_node, int level)
{
	assert(curr_node != NULL);

	fprintf(stderr, "%d%c %p %2d ", level, curr_node->newstr == NULL ? 'N' : 'T', curr_node, curr_node->oldstr_len);
	print_escape(stderr, curr_node->prefix, curr_node->prefix_len);
	fprintf(stderr, "\n");

	for (curr_node = curr_node->child; curr_node != NULL; curr_node = curr_node->next)
		pretree_dump_rec(curr_node, level + 1);
}

static void pretree_dump ()
{
	int i;
	for (i = 0; i < 256; i ++)
		if (pretree_roots[i] != NULL)
			pretree_dump_rec(pretree_roots[i], 0);
}
#endif

/* Recursively insert string (oldstr+curr_ptr) into the subtree curr_node.
 * The returned subtree will replace the passed-in subtree curr_node after calling.
 * Newstr and oldstr can be freed because they will not be reffered to. */
static struct pretree_node *pretree_add_rec (struct pretree_node *curr_node, int curr_ptr,
		const unsigned char *oldstr, int oldstr_len, const unsigned char *newstr_in, int newstr_len)
{
	unsigned char *newstr;
	struct pretree_node *ret_node;
	int count;

	assert(curr_node != NULL);
	assert(oldstr_len > curr_ptr && curr_ptr >= 0);

	/* duplicate newstr */
	if (newstr_len > 0)
		newstr = immortal_alloc(newstr_len, 0, newstr_in);
	else
		newstr = (unsigned char *)"";

	for (count = 0; count < curr_node->prefix_len && count < oldstr_len - curr_ptr; count ++)
		if (curr_node->prefix[count] != oldstr[curr_ptr + count])
			break;

	if (count == curr_node->prefix_len && count == oldstr_len - curr_ptr) {
		/* curr_node->prefix and oldstr+curr_ptr are the same. */
		assert(curr_node->newstr == NULL);
		/* just put newstr in curr_node. */
		curr_node->newstr = newstr;
		curr_node->newstr_len = newstr_len;
		ret_node = curr_node;
	} else if (count == oldstr_len - curr_ptr) {
		/* oldstr+curr_ptr is a prefix of curr_node->prefix. we insert it as curr_node's parent. */
		ret_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
		if (ret_node == NULL)
			FATAL_ERROR("Out of memory. pretree_add_rec()\n");
		ret_node->prefix = curr_node->prefix;
		ret_node->prefix_len = count;
		ret_node->oldstr_len = oldstr_len;
		ret_node->newstr = newstr;
		ret_node->newstr_len = newstr_len;
		ret_node->next = curr_node->next;
		ret_node->child = curr_node;
		curr_node->prefix += count;
		curr_node->prefix_len -= count;
		curr_node->next = NULL;
	} else if (count == curr_node->prefix_len && curr_node->child == NULL) {
		/* curr_node->prefix is a prefix of oldstr+curr_ptr and curr_node is a terminate.
		 * we just add new_node as curr_node's child */
		assert(curr_node->newstr != NULL);
		ret_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
		if (ret_node == NULL)
			FATAL_ERROR("Out of memory. pretree_add_rec()\n");
		ret_node->prefix = immortal_alloc(oldstr_len - curr_ptr - count, 0, oldstr + curr_ptr + count);
		ret_node->prefix_len = oldstr_len - curr_ptr - count;
		ret_node->oldstr_len = oldstr_len;
		ret_node->newstr = newstr;
		ret_node->newstr_len = newstr_len;
		ret_node->next = NULL;
		ret_node->child = NULL;
		curr_node->child = ret_node;
		ret_node = curr_node;
	} else if (count == curr_node->prefix_len) {
		/* curr_node->prefix is a prefix of oldstr+curr_ptr and curr_node is a non-leaf node.
		 * this is the most complicated case and where recursion takes place. */
		struct pretree_node *next_node;
		for (next_node = curr_node->child; next_node != NULL; next_node = next_node->next)
			if (next_node->prefix[0] == oldstr[curr_ptr + count])
				break;
		if (next_node == NULL) {
			/* no matching node is found. we just add a new node as curr_node's child */
			struct pretree_node *new_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
			if (new_node == NULL)
				FATAL_ERROR("Out of memory. pretree_add_rec()\n");
			new_node->prefix = immortal_alloc(oldstr_len - curr_ptr - count, 0, oldstr + curr_ptr + count);
			new_node->prefix_len = oldstr_len - curr_ptr - count;
			new_node->oldstr_len = oldstr_len;
			new_node->newstr = newstr;
			new_node->newstr_len = newstr_len;
			new_node->next = curr_node->child;
			new_node->child = NULL;
			curr_node->child = new_node;
		} else {
			/* found a matching node, and recurse to it.
			 * but first, let's search again to find it's attach point */
			if (next_node == curr_node->child) {
				next_node = pretree_add_rec(next_node, curr_ptr + count, oldstr, oldstr_len, newstr, newstr_len);
				curr_node->child = next_node;
			} else {
				for (ret_node = curr_node->child; ret_node->next != NULL; ret_node = ret_node->next)
					if (ret_node->next == next_node)
						break;
				assert(ret_node != NULL && ret_node->next == next_node);
				next_node = pretree_add_rec(next_node, curr_ptr + count, oldstr, oldstr_len, newstr, newstr_len);
				ret_node->next = next_node;
			}
		}
		ret_node = curr_node;
	} else {
		/* search stopped half way. we need to create a non-terminate parent for the two. */
		/* create the new node first, not the parent */
		struct pretree_node *new_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
		if (new_node == NULL)
			FATAL_ERROR("Out of memory. pretree_add_rec()\n");
		new_node->prefix = immortal_alloc(oldstr_len - curr_ptr - count, 0, oldstr + curr_ptr + count);
		new_node->prefix_len = oldstr_len - curr_ptr - count;
		new_node->oldstr_len = oldstr_len;
		new_node->newstr = newstr;
		new_node->newstr_len = newstr_len;
		new_node->next = curr_node;
		new_node->child = NULL;

		/* now create the non-terminate parent */
		ret_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
		if (ret_node == NULL)
			FATAL_ERROR("Out of memory. pretree_add_rec()\n");
		ret_node->prefix = curr_node->prefix;
		ret_node->prefix_len = count;
		ret_node->oldstr_len = curr_ptr + count;
		ret_node->newstr = NULL;
		ret_node->newstr_len = 0;
		ret_node->next = curr_node->next;
		ret_node->child = new_node;

		curr_node->prefix += count;
		curr_node->prefix_len -= count;
		curr_node->next = NULL;
	}

	return ret_node;
}

/* Data pointed by oldstr and newstr will not be accessed after pretree_add returns,
 * thus caller can free them */
static void pretree_add (const unsigned char *oldstr, int oldstr_len,
		const unsigned char *newstr, int newstr_len)
{
	struct pretree_node *new_node;

	assert(oldstr_len > 0);
	assert(oldstr != NULL);
	assert(newstr_len >= 0);
	assert(newstr_len == 0 || newstr != NULL);

	new_node = pretree_search_len(oldstr, oldstr_len);
	if (new_node != NULL && new_node->oldstr_len == oldstr_len) {
		if (!silent_dup) {
			fprintf(stderr, "Ignored duplicate search string: ");
			print_escape(stderr, oldstr, oldstr_len);
			fprintf(stderr, "\n");
		}
		return;
	}

	if (oldstr_len > longest_oldstr)
		longest_oldstr = oldstr_len;

	if (pretree_roots[(unsigned char)oldstr[0]] != NULL) {
		new_node = pretree_add_rec(pretree_roots[(unsigned char)oldstr[0]],
				0, oldstr, oldstr_len, newstr, newstr_len);
	} else {
		new_node = (struct pretree_node *)immortal_alloc(sizeof(struct pretree_node), 1, NULL);
		if (new_node == NULL)
			FATAL_ERROR("Out of memory. pretree_add()\n");
		new_node->prefix = immortal_alloc(oldstr_len, 0, oldstr);
		new_node->prefix_len = oldstr_len;
		new_node->oldstr_len = oldstr_len;
		new_node->newstr = newstr_len == 0 ? (unsigned char *)"" : immortal_alloc(newstr_len, 0, newstr);
		new_node->newstr_len = newstr_len;
		new_node->next = NULL;
		new_node->child = NULL;
	}
	pretree_roots[(unsigned char)oldstr[0]] = new_node;
}

/* Data pointed by oldexp and newexp will not be accessed after pretree_add_exp returns,
 * thus caller can free them. */
static void pretree_add_exp (const char *oldexp, const char *newexp, int ishex)
{
	unsigned char *oldstr, *newstr;
	int oldstr_len, newstr_len;

	assert(oldexp != NULL);
	assert(oldexp[0] != '\0');

	if (ishex) {
		oldstr_len = strlen(oldexp) / 2;
		if (oldstr_len == 0) /* means strlen(oldexp) = 1 */
			FATAL_ERROR("Hexstring %s is not even in length\n", oldexp);
		oldstr = (unsigned char *)malloc(oldstr_len);
		unhex(oldstr, oldexp);
		if (newexp == NULL || newexp[0] == '\0' || newexp[1] == '\0') {
			newstr = NULL;
			newstr_len = 0;
		} else {
			newstr_len = strlen(newexp) / 2;
			newstr = (unsigned char *)malloc(newstr_len);
			unhex(newstr, newexp);
		}
	} else {
		oldstr = (unsigned char *)malloc(strlen(oldexp) + 1);
		oldstr_len = unescape(oldstr, oldexp);
		if (newexp == NULL || newexp[0] == '\0') {
			newstr = NULL;
			newstr_len = 0;
		} else {
			newstr = (unsigned char *)malloc(strlen(newexp) + 1);
			newstr_len = unescape(newstr, newexp);
		}
	}

	pretree_add(oldstr, oldstr_len, newstr, newstr_len);

	free(oldstr);
	if (newstr != NULL)
		free(newstr);

#ifdef DEBUG
	fprintf(stderr, "added \"%s\"\n", oldexp);
	pretree_dump();
#endif
}

static void replace_fp (FILE *infp, FILE *outfp)
{
	int ptr_buff, ptr_curr, ptr_limit, ptr_size;
	struct pretree_node *node;

	ptr_size = 0;
	while (!feof(infp)) {
		ptr_size += fread(inbuff + ptr_size, 1, inbuff_size - ptr_size, infp);

		ptr_buff = ptr_curr = 0;
		ptr_limit = ptr_size - longest_oldstr;
		while (ptr_curr <= ptr_limit) {
			if ((node = pretree_search(inbuff + ptr_curr))) {
				if (ptr_buff < ptr_curr)
					fwrite(inbuff + ptr_buff, 1, ptr_curr - ptr_buff, outfp);
				if (node->newstr_len != 0)
					fwrite(node->newstr, 1, node->newstr_len, outfp);
				ptr_curr += node->oldstr_len;
				ptr_buff = ptr_curr;
			} else {
				ptr_curr ++;
			}
		}

		if (ptr_buff < ptr_curr)
			fwrite(inbuff + ptr_buff, 1, ptr_curr - ptr_buff, outfp);

		if (ptr_curr != 0) {
			memmove(inbuff, inbuff + ptr_curr, ptr_size - ptr_curr);
			ptr_size -= ptr_curr;
		}
	}

	ptr_buff = ptr_curr = 0;
	while (ptr_curr < ptr_size) {
		if ((node = pretree_search_len(inbuff + ptr_curr, ptr_size - ptr_curr))) {
			if (ptr_buff < ptr_curr)
				fwrite(inbuff + ptr_buff, 1, ptr_curr - ptr_buff, outfp);
			if (node->newstr_len != 0)
				fwrite(node->newstr, 1, node->newstr_len, outfp);
			ptr_curr += node->oldstr_len;
			ptr_buff = ptr_curr;
		} else {
			ptr_curr ++;
		}
	}
	if (ptr_buff < ptr_curr)
		fwrite(inbuff + ptr_buff, 1, ptr_curr - ptr_buff, outfp);
}

static void replace_file_mem (int size, FILE *outfp)
{
	int count = 0, buffptr = 0;
	while (count < size) {
		struct pretree_node *node =
			pretree_search_len(inbuff + count, size - count);
		if (node) {
			if (buffptr < count)
				fwrite(inbuff + buffptr, 1, count - buffptr, outfp);
			if (node->newstr_len > 0)
				fwrite(node->newstr, 1, node->newstr_len, outfp);
			count += node->oldstr_len;
			buffptr = count;
		} else {
			count ++;
		}
	}
	if (buffptr < count)
		fwrite(inbuff + buffptr, 1, count - buffptr, outfp);
}

/* returns 0 if file/dir exists, 1 if not exist and can create */
int file_not_exist (const char *path)
{
#ifdef BR_WINDOWS
	// should use INVALID_FILE_ATTRIBUTES instead of -1, but ...
	return (GetFileAttributes(path) == ((DWORD)(-1)) && GetLastError() == ERROR_FILE_NOT_FOUND);
#else
	struct stat st;

	return (stat(path, &st) != 0 && errno == ENOENT);
#endif
}


/* first try origfilename.br
 * then try origfilename.br.ddd 10 times with random 000<=ddd<=999
 */
static char *get_temp_file_name (const char *origfilename)
{
	static char newfilename [256];
	int org_len, i, ddd;

	org_len = strlen(origfilename);
	if (org_len > 255 - 8)
		return NULL;
	strncpy(newfilename, origfilename, 256);

	strncpy(newfilename + org_len, ".br", 4);
	if (file_not_exist(newfilename))
		return newfilename;

	for (i = 0; i < 10; i ++) {
		ddd = rand() % 1000;
		sprintf(newfilename + org_len + 3, ".%03d", ddd);
		if (file_not_exist(newfilename))
			return newfilename;
	}

	return NULL;
}

static int replace_file (const char *infilename, const char *outfilename)
{
	FILE *fp = NULL;
	int size;

	fp = fopen(infilename, "rb");
	if (fp == NULL) {
		perror(infilename);
		goto error_out;
	}
	setvbuf(fp, NULL, _IONBF, 0);

	if (fseek(fp, 0, SEEK_END)) {
		perror(infilename);
		goto error_out;
	}
	size = ftell(fp);
	if (size < 0) {
		perror(infilename);
		goto error_out;
	}
	rewind(fp);

	if (size == 0) { // empty input file
		fclose(fp);
		if (strcmp(infilename, outfilename) != 0) {
			fp = fopen(outfilename, "wb");
			if (fp == NULL) {
				perror(outfilename);
				goto error_out;
			}
			fclose(fp);
		}
	} else if (size <= inbuff_size) { // small input file
		if(fread(inbuff, 1, size, fp) != size) {
			perror(infilename);
			goto error_out;
		}
		fclose(fp);

		fp = fopen(outfilename, "wb");
		if (fp == NULL) {
			perror(outfilename);
			goto error_out;
		}

		replace_file_mem(size, fp);

		fclose(fp);
	} else if (strcmp(infilename, outfilename) != 0) { // large input file, output file is different from input file
		FILE *outfp;

		outfp = fopen(outfilename, "wb");
		if (fp == NULL) {
			perror(outfilename);
			goto error_out;
		}

		replace_fp(fp, outfp);

		fclose(fp);
		fclose(outfp);
	} else { // large input file, output file is same as input file
		char *tempfilename;
		FILE *outfp;

		tempfilename = get_temp_file_name(infilename);
		if (tempfilename == NULL) {
			perror(infilename);
			goto error_out;
		}

		outfp = fopen(tempfilename, "wb");
		if (fp == NULL) {
			perror(tempfilename);
			goto error_out;
		}

		replace_fp(fp, outfp);

		fclose(fp);
		fclose(outfp);

		if (remove(infilename)) {
			perror(infilename); //FIXME: this is a serious error. because it's stoped halfway.
			goto error_out;
		}

		if (rename(tempfilename, infilename)) {
			perror(tempfilename); //FIXME: this is a serious error. because it's stoped halfway.
			goto error_out;
		}
	}

	return 0;
error_out:
	if (fp != NULL)
		fclose(fp);
	return -1;
}

static void print_usage (void)
{
	printf(
		"binreplace -- binary string search & replace tool\n"
		"Usage:\n"
		"  binreplace [OPTIONS] [input-file]...\n"
		"Options:\n"
		"  -r search-term replace-term\n"
		"    Replace search-term with replace-term\n"
		"    Escape sequence applies to search-term and replace-term.\n"
		"  -R search-term replace-term\n"
		"    Replace search-term with replace-term\n"
		"    search-term and replace-term are hexstrings\n"
		"  -d search-term\n"
		"    Delete search-term\n"
		"    Escape sequence applies to search-term.\n"
		"  -D search-term\n"
		"    Delete search-term\n"
		"    search-term is hexstring\n"
		"  -f listing-file\n"
		"    Load search and replace strings from listing-file\n"
		"    The format of the listing-file is tab-separated-veriable.\n"
		"    Each line contains one (delete) or two (replace) fields.\n"
		"    Escape sequence applies.\n"
		"  -F listing-file\n"
		"    Same as -f, but use hexstring.\n"
		"  -i[SUFFIX]\n"
		"    Replace files in place (makes backup if extension supplied)\n"
		"    Do not use with -o\n"
		"  -g\n"
		"    Suppress warning of duplicate search terms\n"
		"  -s size\n"
		"    Use size as input buffer size\n"
		"  -o output-file\n"
		"    Write output to output-file instead of stdout.\n"
		"    Do not use with -i\n"
		"    Do not use the same output file as input file. Use -i instead.\n"
		"  -h, -?, --help\n"
		"    Print this help message.\n"
		"  input-file\n"
		"    Stdin is used if there is no input files\n"
		"Example: (assuming the bash shell)\n"
		"  1. Replace \"cow\" with \"sheep\" and \"cat\" with \"dog\" from document.txt into foo.txt.\n"
		"  binreplace -r cow sheep -r cat dog <document.txt >foo.txt\n"
		"  2. Replace \"i\" with \"I\" but keep \"int\" untouched.\n"
		"  binreplace -r i I -r int int\n"
		"  3. Translate foo.txt from dos format into unix format. (Use double slash to escape slash from bash)\n"
		"  binreplace -r \\\\r '' -i foo.txt\n"
		"  4. Same as above.\n"
		"  binreplace -d \\\\r -i foo.txt\n"
		"  5. Translate the file foo.txt from unix format into dos format.\n"
		"  binreplace -r \\\\r '' -r \\\\n \\\\r\\\\n -i foo.txt\n"
		"  6. Same as above.\n"
		"  binreplace -D 0d -R 0a 0d0a -i foo.txt\n"
		"  7. Replace \"colour\" to \"color\" in all the files in /foo, making use of the find(1) utility.\n"
		"  find /foo -type f -print0 | xargs -0 binreplace -i -r colour color\n"
		"  8. Load search-term and replace-term pairs from listfile.txt.\n"
		"  One pair each line; search-term and newstring are separated by tab; escape sequence applies\n"
		"  binreplace -f listfile.txt\n"
		"Escape sequence:\n"
		"  \\n, \\r, \\t, \\\\\n"
		"  \\0: This is useful for binary file\n"
		"  \\xhh: hexadecimal value of a byte\n"
		"Replace once property:\n"
		"  The replaced string will not be searched again.\n"
		"Greedy longest first property:\n"
		"  For two overlapping matches, the earlier one (with smaller offset) will be replaced.\n"
		"  When two offsets are the same, the longer one is replaced.\n"
		"\n");
	exit(0);
}

int main (int argc, char *argv[])
{
	int arg_count;
	struct file_struct *files_head = NULL, *files_tail = NULL;
	char *inplace_str = NULL;
	char *out_filepath = NULL;

	arg_count = 1;
	while (arg_count < argc) {
		if (strcmp("-h", argv[arg_count]) == 0 ||
				strcmp("--help", argv[arg_count]) == 0 ||
				strcmp("-?", argv[arg_count]) == 0) {
			print_usage();
		} else if (strcmp("-r", argv[arg_count]) == 0 || strcmp("-R", argv[arg_count]) == 0) {
			if (arg_count + 2 >= argc)
				FATAL_ERROR("expect \"-r/R search-term replace-term\"\n");
			if (argv[arg_count + 1][0] == '\0')
				FATAL_ERROR("search-term can't be empty.\n");
			pretree_add_exp(argv[arg_count + 1], argv[arg_count + 2], argv[arg_count][1] == 'R');
			arg_count += 3;
		} else if (strcmp("-d", argv[arg_count]) == 0 || strcmp("-D", argv[arg_count]) == 0) {
			if (arg_count + 1 >= argc)
				FATAL_ERROR("expect \"-d/D search-term\"\n");
			if (argv[arg_count + 1][0] == '\0')
				FATAL_ERROR("search-term can't be empty.\n");
			pretree_add_exp(argv[arg_count + 1], NULL, argv[arg_count][1] == 'D');
			arg_count += 2;
		} else if (strcmp("-f", argv[arg_count]) == 0 || strcmp("-F", argv[arg_count]) == 0) {
			FILE *fp = fopen(argv[arg_count + 1], "r");
			if (fp == NULL)
				FATAL_ERROR("cannot read %s\n", argv[arg_count + 1]);

			while (1) {
				char line[8192]; //TODO: should support long line
				int line_length;
				char *newexp;

				/* 1. read a line */
				if (fgets(line, sizeof(line), fp) == NULL)
					break;
				line_length = strlen(line);
				if (line_length == 0)
					continue;
				if (line_length == sizeof(line) - 1)
					FATAL_ERROR("file %s has very long line. line should be shorter than %d bytes\n",
							argv[arg_count + 1], (int)sizeof(line) - 2);
				if (line[line_length - 1] == '\r' || line[line_length - 1] == '\n') {
					line_length --;
					if (line[line_length - 1] == '\r' || line[line_length - 1] == '\n')
						line_length --;
					line[line_length] = '\0';
				}

				/* 2. prepare oldexp (same as line) and newexp */
				if (line[0] == '\t')
					FATAL_ERROR("Line starts with tab. old string can't be empty.\n");
				newexp = strchr(line, '\t');
				if (newexp != NULL) {
					*newexp = '\0';
					newexp ++;
				}

				/* 3. add the term */
				pretree_add_exp(line, newexp, argv[arg_count][1] == 'F');
			}

			fclose(fp);

			arg_count += 2;
		} else if (memcmp("-i", argv[arg_count], 2) == 0) {
			inplace_str = argv[arg_count] + 2;
			arg_count ++;
		} else if (strcmp("-g", argv[arg_count]) == 0) {
			silent_dup = 1;
			arg_count ++;
		} else if (strcmp("-s", argv[arg_count]) == 0) {
			if (arg_count + 1 >= argc || atoi(argv[arg_count + 1]) <= 0)
				FATAL_ERROR("expect \"-s number\"\n");
			if (atoi(argv[arg_count + 1]) < 32)
				fprintf(stderr, "buffer size too small. Used default size.\n");
			else
				inbuff_size = atoi(argv[arg_count + 1]);
			arg_count += 2;
		} else if (strcmp("-o", argv[arg_count]) == 0) {
			if (arg_count + 1 >= argc)
				FATAL_ERROR("expect \"-o output-file\"\n");
			out_filepath = argv[arg_count + 1];
			arg_count += 2;
		} else if (strcmp("--", argv[arg_count]) == 0) {
			arg_count ++;
			break;
		} else if (argv[arg_count][0] == '-') { /* No. Can't use - as stdin. */
			FATAL_ERROR("unexpected option %s\n", argv[arg_count]);
		} else {
			struct file_struct *new_file = (struct file_struct *)immortal_alloc(sizeof(struct file_struct), 1, NULL);
			new_file->next = NULL;
			if (files_tail == NULL)
				files_head = files_tail = new_file;
			else
				files_tail = files_tail->next = new_file;
			new_file->path = argv[arg_count];
			arg_count ++;
		}
	}

	while (arg_count < argc) {
		struct file_struct *new_file = (struct file_struct *)immortal_alloc(sizeof(struct file_struct), 1, NULL);
		new_file->next = NULL;
		if (files_tail == NULL)
			files_head = files_tail = new_file;
		else
			files_tail = files_tail->next = new_file;
		new_file->path = argv[arg_count];
		arg_count ++;
	}

	/* check if there is any search term */
	{
		int i;
		for (i = 0; i < 256; i ++)
			if (pretree_roots[i] != NULL)
				break;
		if (i == 256)
			FATAL_ERROR("no search expression specified. There should be atlease one.\n");
	}

	/* check inplace usage */
	if (inplace_str != NULL) {
		if (out_filepath != NULL)
			FATAL_ERROR("-o can't be used with -i\n");
		if (files_head == NULL)
			FATAL_ERROR("can't use -i without any input file specified.\n");
	}

	/* check input file existance */
	{
		struct file_struct *curr;
		for (curr = files_head; curr != NULL; curr = curr->next) {
			FILE *fp = fopen(curr->path, "rb");
			if (fp == NULL) {
				perror(curr->path);
				FATAL_ERROR("input file error. nothing changed.\n");
			}
			fclose(fp);
		}
	}

	/* multiple input files and output file is in one of them?
	 * This is just a helpful checking, not grantee. (e.g. binreplace ... a b ./a) */
	if (files_head != NULL && files_head->next != NULL && out_filepath != NULL) {
		struct file_struct *curr;
		for (curr = files_head; curr != NULL; curr = curr->next)
			if (strcmp(curr->path, out_filepath) == 0)
				FATAL_ERROR("Don't use same input as output file. use -i instead.\n");
	}

	/* must be significantly larger than search string */
	if (inbuff_size < 8 * longest_oldstr)
		inbuff_size = 8 * longest_oldstr;
	inbuff = (unsigned char *)malloc(inbuff_size);
	if (inbuff == NULL)
		FATAL_ERROR("Out of memory. Try smaller buffer size\n");

#ifdef DEBUG
	pretree_dump();
#endif

	if (inplace_str == NULL) {
		/* Let's fix a special case when there is one input file and -o is used
		 * If they are the same, we have to use replace_file. */
		if (out_filepath != NULL && files_head != NULL && files_head->next == NULL) {
			replace_file(files_head->path, out_filepath);
		} else {
			FILE *out_fp = out_filepath == NULL ? stdout : fopen(out_filepath, "wb");
			if (out_fp == NULL)
				FATAL_ERROR("can't write to %s\n", out_filepath);
			if (files_head == NULL) { /* stdio mode */
				setvbuf(stdin, NULL, _IONBF, 0);
				replace_fp(stdin, stdout);
			} else {
				struct file_struct *curr;
				for (curr = files_head; curr != NULL; curr = curr->next) {
					FILE *in_fp = fopen(curr->path, "rb");
					if (in_fp == NULL) {
						perror(curr->path);
						continue;
					}
					replace_fp(in_fp, out_fp);
					fclose(in_fp);
				}
			}
			if (out_fp != stdout)
				fclose(out_fp);
		}
	} else { /* inplace */
		struct file_struct *curr;
		for (curr = files_head; curr != NULL; curr = curr->next) {
			char *backup;

			if (inplace_str[0] == '\0') {
				replace_file(curr->path, curr->path);
				continue;
			}

			backup = malloc(strlen(curr->path) + strlen(inplace_str) + 1);
			strcpy(backup, curr->path);
			strcat(backup, inplace_str);
			if (rename(curr->path, backup)) {
 				perror("curr->path");
 				free(backup);
 				continue;
 			}
			replace_file(backup, curr->path);
			free(backup);
		}
	}

	return 0;
}
