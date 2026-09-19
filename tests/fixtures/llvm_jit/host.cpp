// Exercise registration and removal through LLVM's MCJIT implementation.
// stdin: remove, replace, exit. stdout: ready <leaf address>, removed.
#include <llvm/BinaryFormat/Magic.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>

#include <cstdlib>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

// Public GDB JIT ABI, used only to inspect LLVM's registrations. Older LLVM
// releases define these structures internally rather than in an installed header.
struct jit_code_entry {
  jit_code_entry *next_entry;
  jit_code_entry *prev_entry;
  const char *symfile_addr;
  uint64_t symfile_size;
};

struct jit_descriptor {
  uint32_t version;
  uint32_t action_flag;
  jit_code_entry *relevant_entry;
  jit_code_entry *first_entry;
};

/// Fail loudly if LLVM cannot provide the lifecycle this fixture exercises.
static void require(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "LLVM JIT fixture: " << message << '\n';
    std::exit(1);
  }
}

/// Read LLVM's own registry. Only the main thread creates or destroys engines.
static jit_descriptor &registry() {
  auto *descriptor = static_cast<jit_descriptor *>(
      dlsym(RTLD_DEFAULT, "__jit_debug_descriptor"));
  require(descriptor != nullptr, "LLVM has no GDB JIT descriptor");
  require(descriptor->version == 1, "unsupported GDB JIT descriptor version");
  return *descriptor;
}

/// Keep one engine alive until its generated worker has stopped.
class GeneratedProgram {
  llvm::LLVMContext context;
  std::unique_ptr<llvm::ExecutionEngine> engine;
  std::thread worker;
  alignas(4) uint32_t stop = 0;

public:
  /// Compile ordinary LLVM IR and let LLVM publish its ELF and unwind tables.
  GeneratedProgram(const char *path, const std::string &generation) {
    require(registry().first_entry == nullptr, "previous engine is registered");
#if LLVM_VERSION_MAJOR < 15
    context.enableOpaquePointers();
#endif
    llvm::SMDiagnostic diagnostic;
    auto module = llvm::parseIRFile(path, diagnostic, context);
    if (!module) {
      diagnostic.print("LLVM JIT fixture", llvm::errs());
      std::exit(1);
    }
    for (auto &function : *module)
      function.setName(function.getName().str() + "_" + generation);

    std::string error;
    engine.reset(llvm::EngineBuilder(std::move(module))
                     .setEngineKind(llvm::EngineKind::JIT)
                     .setErrorStr(&error)
                     .create());
    require(engine != nullptr, "cannot create MCJIT engine: " + error);
    // MCJIT installs LLVM's GDB listener when the engine is created.
    engine->finalizeObject();

    auto leaf = engine->getFunctionAddress("llvm_leaf_" + generation);
    auto entry = engine->getFunctionAddress("llvm_entry_" + generation);
    require(leaf != 0 && entry != 0, "generated functions are missing");
    const auto *registration = registry().first_entry;
    require(registration != nullptr && registration->next_entry == nullptr,
            "expected one LLVM GDB registration");
    require(llvm::identify_magic(llvm::StringRef(registration->symfile_addr,
                                                registration->symfile_size)) ==
                llvm::file_magic::elf_relocatable,
            "LLVM registration does not contain an ELF object");

    worker = std::thread([this, entry] {
      reinterpret_cast<void (*)(uint32_t *)>(entry)(&stop);
    });
    std::cout << "ready " << std::hex << leaf << std::dec << std::endl;
  }

  /// Join before freeing executable memory, then verify LLVM unregistered it.
  ~GeneratedProgram() {
    // Pair with the LLVM IR's atomic load; neither side accesses stop nonatomically.
    __atomic_store_n(&stop, 1U, __ATOMIC_RELEASE);
    worker.join();
    engine.reset();
    require(registry().first_entry == nullptr,
            "destroying MCJIT did not remove its GDB registration");
  }
};

/// Acknowledge transitions only after compilation or destruction has finished.
int main(int argc, char **argv) {
  require(argc == 2, "usage: llvm-jit-host program.ll");
  require(!llvm::InitializeNativeTarget(), "cannot initialize native target");
  require(!llvm::InitializeNativeTargetAsmPrinter(), "cannot initialize assembler");
  auto program = std::make_unique<GeneratedProgram>(argv[1], "first");
  std::string command;
  while (std::getline(std::cin, command)) {
    if (command == "remove") {
      require(program != nullptr, "remove requires a live engine");
      program.reset();
      std::cout << "removed" << std::endl;
    } else if (command == "replace") {
      require(program == nullptr, "replace requires the old engine to be removed");
      program = std::make_unique<GeneratedProgram>(argv[1], "second");
    } else if (command == "exit") {
      break;
    } else {
      require(false, "unknown command: " + command);
    }
  }
}
