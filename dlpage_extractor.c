
#define Q6ZIP_PAGE_SIZE 4096

#define Q6ZIP_DICT1_BITS 10
#define Q6ZIP_DICT2_BITS 12

/* These addresses has to be extracted from device. */
#define Q6ZIP_RO_ADDR 0x8a179000
#define Q6ZIP_RO_SIZE 0xa9f238
#define Q6ZIP_RW_ADDR 0x8ac1a000
#define Q6ZIP_RW_SIZE 0x14158

#define DLPAGE_RO_ADDR 0xd0000000
#define DLPAGE_RW_ADDR 0xd11b3000

#define Q6ZIP_RO_UNCOMPRESS_FUNC 0x88037030
#define Q6ZIP_RW_UNCOMPRESS_FUNC 0x880379B0

typedef int (*q6zip_ro_uncompress_t)(long out_addr, int *out_size, long in_addr, int in_size, long dict);
typedef int (*q6zip_rw_uncompress_t)(long in_addr, /*int in_size, */long out_addr, int out_size);

static q6zip_ro_uncompress_t q6zip_ro_uncompress = (q6zip_ro_uncompress_t) Q6ZIP_RO_UNCOMPRESS_FUNC;
static q6zip_rw_uncompress_t q6zip_rw_uncompress = (q6zip_rw_uncompress_t) Q6ZIP_RW_UNCOMPRESS_FUNC;

static int do_ro(void)
{
	int nb;
	int i;
	unsigned long *index;
	unsigned long dict;
	unsigned long addr;
	int size;

	nb = *((int *)Q6ZIP_RO_ADDR);
	dict = Q6ZIP_RO_ADDR + 4;
	index = (void *)(Q6ZIP_RO_ADDR + 4 + ((1 << Q6ZIP_DICT1_BITS) + (1 << Q6ZIP_DICT2_BITS)) * 4);
	addr = DLPAGE_RO_ADDR;
	for (i = 0; i < nb; i++) {
		unsigned long va1, va2;

		if (i < nb - 1) {
			va1 = index[i];
			va2 = index[i + 1];
		} else {
			va1 = index[i];
			va2 = Q6ZIP_RO_ADDR + Q6ZIP_RO_SIZE;
		}
		q6zip_ro_uncompress(addr, &size, va1, va2 - va1, dict);
		addr += Q6ZIP_PAGE_SIZE;
	}
	return 0;
}

static int do_rw(void)
{
	int nb;
	int i;
	unsigned long *index;
	unsigned long addr;

	nb = *((short *)Q6ZIP_RW_ADDR);
	index = (void *)(Q6ZIP_RW_ADDR + 4);
	addr = DLPAGE_RW_ADDR;
	for (i = 0; i < nb; i++) {
		unsigned long va;

		va = index[i];
		q6zip_rw_uncompress(va, addr, Q6ZIP_PAGE_SIZE);
		addr += Q6ZIP_PAGE_SIZE;
	}
	return 0;
}

int main()
{
	do_ro();
	do_rw();
	// make gdb stop here
	*((int *)0xdead0000) = 0xbaad000;
	return 0;
}

