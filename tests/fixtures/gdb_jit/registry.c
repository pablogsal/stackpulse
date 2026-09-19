#include <stdint.h>

/* The descriptor and linked entries are the GDB JIT registration ABI. */
struct jit_code_entry {
    struct jit_code_entry *next, *prev;
    const char *symfile_addr;
    uint64_t symfile_size;
};
struct jit_descriptor {
    uint32_t version, action;
    struct jit_code_entry *relevant, *first;
};

#if defined(REGISTRY_LIBRARY) || defined(EXECUTABLE_REGISTRY)
struct jit_descriptor __jit_debug_descriptor = {1, 0, 0, 0};
#endif

#ifndef REGISTRY_LIBRARY
#include <dlfcn.h>
#include <elf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct jit_object {
    char *image;
    size_t image_size;
    char *code;
    Elf64_Ehdr *header;
    Elf64_Shdr *sections;
    char *leaf_name;
    void (*leaf)(void);
};

static struct jit_object object;
static struct jit_code_entry entry;
static struct jit_descriptor *active_registry;
#ifdef RECOVER_CFI
static void *cfi_page;
static char *saved_cfi_page;
static size_t page_size;
#endif

/* Read the assembler/linker output, retaining its section and symbol tables. */
static void read_object(struct jit_object *object) {
    FILE *file = fopen(JIT_OBJECT, "rb");
    if (!file || fseek(file, 0, SEEK_END)) abort();
    long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET)) abort();
    object->image_size = (size_t)size;
    object->image = malloc(object->image_size);
    if (!object->image ||
        fread(object->image, 1, object->image_size, file) != object->image_size) abort();
    fclose(file);
    object->header = (Elf64_Ehdr *)object->image;
    object->sections = (Elf64_Shdr *)(object->image + object->header->e_shoff);
}

/* Preserve linked section spacing so PC-relative .eh_frame addresses stay valid. */
static void map_allocated_sections(struct jit_object *object) {
    size_t extent = 0;
    for (size_t i = 0; i < object->header->e_shnum; i++) {
        const Elf64_Shdr *section = &object->sections[i];
        if ((section->sh_flags & SHF_ALLOC) && section->sh_addr + section->sh_size > extent)
            extent = section->sh_addr + section->sh_size;
    }
#ifdef NAMED_MAPPING
    FILE *backing = tmpfile();
    if (!backing || ftruncate(fileno(backing), extent)) abort();
    object->code = mmap(NULL, extent, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE, fileno(backing), 0);
    fclose(backing);
#else
    object->code = mmap(NULL, extent, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (object->code == MAP_FAILED) abort();
    for (size_t i = 0; i < object->header->e_shnum; i++) {
        const Elf64_Shdr *section = &object->sections[i];
        if ((section->sh_flags & SHF_ALLOC) && section->sh_type != SHT_NOBITS)
            memcpy(object->code + section->sh_addr,
                   object->image + section->sh_offset, section->sh_size);
    }
}

/* Present the linked code as an ET_REL registration with section-relative symbols. */
static void relocate_registration(struct jit_object *object) {
    for (size_t i = 0; i < object->header->e_shnum; i++) {
        const Elf64_Shdr *section = &object->sections[i];
        if (section->sh_type != SHT_SYMTAB) continue;
        Elf64_Sym *symbols = (Elf64_Sym *)(object->image + section->sh_offset);
        char *names = object->image + object->sections[section->sh_link].sh_offset;
        for (size_t j = 0; j < section->sh_size / sizeof(*symbols); j++) {
            Elf64_Sym *symbol = &symbols[j];
            if (symbol->st_shndx == SHN_UNDEF || symbol->st_shndx >= object->header->e_shnum)
                continue;
            if (strcmp(names + symbol->st_name, "registered_leaf") == 0) {
                object->leaf = (void (*)(void))(object->code + symbol->st_value);
                object->leaf_name = names + symbol->st_name;
            }
            symbol->st_value -= object->sections[symbol->st_shndx].sh_addr;
        }
    }
    for (size_t i = 0; i < object->header->e_shnum; i++) {
        Elf64_Shdr *section = &object->sections[i];
        if (section->sh_flags & SHF_ALLOC)
            section->sh_addr += (uintptr_t)object->code;
    }
    object->header->e_type = ET_REL;
    if (!object->leaf || !object->leaf_name) abort();
}

/* Only live CFI is usable: the registration contains a terminated empty table. */
static void prepare_unwind_data(struct jit_object *object) {
    const char *names = object->image +
        object->sections[object->header->e_shstrndx].sh_offset;
    for (size_t i = 0; i < object->header->e_shnum; i++) {
        Elf64_Shdr *section = &object->sections[i];
        if (strcmp(names + section->sh_name, ".eh_frame") != 0) continue;
        memset(object->image + section->sh_offset, 0, section->sh_size);
#ifdef RECOVER_CFI
        page_size = (size_t)sysconf(_SC_PAGESIZE);
        cfi_page = (void *)(section->sh_addr & ~(uintptr_t)(page_size - 1));
        if (section->sh_addr + section->sh_size > (uintptr_t)cfi_page + page_size)
            abort();
        saved_cfi_page = malloc(page_size);
        if (!saved_cfi_page) abort();
        memcpy(saved_cfi_page, cfi_page, page_size);
        /* /proc/pid/mem ignores PROT_NONE, so make the page truly absent. */
        if (munmap(cfi_page, page_size)) abort();
#endif
        return;
    }
    abort();
}

/* Resolve the library registry unless the executable interposes its own symbol. */
static struct jit_descriptor *find_registry(void) {
    void *library = dlopen(JIT_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        abort();
    }
#ifdef EXECUTABLE_REGISTRY
    return &__jit_debug_descriptor;
#else
    struct jit_descriptor *registry = dlsym(library, "__jit_debug_descriptor");
    if (!registry) abort();
    return registry;
#endif
}

/* Reuse the same entry and ELF allocation to exercise registration identity. */
static void register_object(void) {
    active_registry->first = active_registry->relevant = &entry;
    active_registry->action = 1;
}

#if defined(LIFECYCLE) || defined(RECOVER_CFI)
/* Signals mark observable phases while execution remains in the generated leaf. */
static void update_registry(int signum) {
#ifdef RECOVER_CFI
    (void)signum;
    if (mmap(cfi_page, page_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != cfi_page)
        _exit(1);
    for (size_t i = 0; i < page_size; i++)
        ((char *)cfi_page)[i] = saved_cfi_page[i];
#else
    if (signum == SIGUSR1) {
        active_registry->first = 0;
        active_registry->action = 2;
    } else {
        const char replacement[] = "replacement_jit";
        for (size_t i = 0; i < sizeof(replacement); i++)
            object.leaf_name[i] = replacement[i];
        register_object();
    }
#endif
    (void)write(STDOUT_FILENO, "changed\n", 8);
}
#endif

/* Remain visible as the caller beneath the frame-pointer-free generated leaf. */
__attribute__((noinline)) static void jit_caller(void) {
    object.leaf();
    abort();
}

int main(void) {
    active_registry = find_registry();
    read_object(&object);
    map_allocated_sections(&object);
    relocate_registration(&object);
    prepare_unwind_data(&object);
    entry.symfile_addr = object.image;
    entry.symfile_size = object.image_size;
    register_object();
#if defined(LIFECYCLE) || defined(RECOVER_CFI)
    signal(SIGUSR1, update_registry);
    signal(SIGUSR2, update_registry);
#endif
    printf("ready %lx\n", (unsigned long)(uintptr_t)object.leaf + 4);
    fflush(stdout);
    jit_caller();
}
#endif
