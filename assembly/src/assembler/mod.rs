use super::{
    parsers::{self, Instruction, Node, ProcedureAst, ProgramAst},
    AssemblyError, BTreeMap, Box, CallSet, CodeBlock, CodeBlockTable, Felt, Kernel, ModuleAst,
    ModuleProvider, Operation, Procedure, ProcedureId, Program, String, ToString, Vec, ONE, ZERO,
};
use core::{borrow::Borrow, pin::Pin};
use vm_core::{utils::group_vector_elements, Decorator, DecoratorList};

mod instruction;

mod span_builder;
use span_builder::SpanBuilder;

mod context;
use context::AssemblyContext;

#[cfg(test)]
mod tests;

// TYPE ALIASES
// ================================================================================================

type ProcedureCache = BTreeMap<ProcedureId, Procedure>;

// ASSEMBLER
// ================================================================================================
/// Miden Assembler which can be used to convert Miden assembly source code into program MAST (
/// represented by the [Program] struct). The assembler can be instantiated in several ways using
/// a "builder" patter. Specifically:
/// - If `with_kernel()` or `with_kernel_module()` methods are not used, the assembler will be
///   instantiated with a default empty kernel. Programs compiled using such assembler
///   cannot make calls to kernel procedures via `syscall` instruction.
/// - If `with_module_provider()` method is not used, the assembler will be instantiated without
///   access to external libraries. Programs compiled with such assembler must be self-contained
///   (i.e., they cannot invoke procedures from external libraries).
pub struct Assembler {
    kernel: Kernel,
    module_provider: Box<dyn ModuleProvider>,
    proc_cache: Pin<Box<ProcedureCache>>,
    in_debug_mode: bool,
}

impl Assembler {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [Assembler] instantiated with empty module map.
    pub fn new() -> Self {
        Self {
            kernel: Kernel::default(),
            module_provider: Box::new(()),
            proc_cache: Box::pin(BTreeMap::default()),
            in_debug_mode: false,
        }
    }

    /// Puts the assembler into the debug mode.
    pub fn with_debug_mode(mut self, in_debug_mode: bool) -> Self {
        self.in_debug_mode = in_debug_mode;
        self
    }

    /// Adds the specified [ModuleProvider] to the assembler.
    pub fn with_module_provider<P>(mut self, provider: P) -> Self
    where
        P: ModuleProvider + 'static,
    {
        self.module_provider = Box::new(provider);
        self
    }

    /// Sets the kernel for the assembler to the kernel defined by the provided source.
    ///
    /// # Errors
    /// Returns an error if compiling kernel source results in an error.
    ///
    /// # Panics
    /// Panics if the assembler has already been used to compile programs.
    pub fn with_kernel(self, kernel_source: &str) -> Result<Self, AssemblyError> {
        let kernel_ast = parsers::parse_module(kernel_source)?;
        self.with_kernel_module(&kernel_ast)
    }

    /// Sets the kernel for the assembler to the kernel defined by the provided module.
    ///
    /// # Errors
    /// Returns an error if compiling kernel source results in an error.
    pub fn with_kernel_module(mut self, module: &ModuleAst) -> Result<Self, AssemblyError> {
        // compile the kernel; this adds all exported kernel procedures to the procedure cache
        let mut context = AssemblyContext::new(true);
        self.compile_module(module, ProcedureId::KERNEL_PATH, &mut context)?;

        // convert the context into Kernel; this builds the kernel from hashes of procedures
        // exported form the kernel module
        self.kernel = context.into_kernel();

        Ok(self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this assembler was instantiated in debug mode.
    pub fn in_debug_mode(&self) -> bool {
        self.in_debug_mode
    }

    /// Returns a reference to the kernel for this assembler.
    ///
    /// If the assembler was instantiated without a kernel, the internal kernel will be empty.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    // PROGRAM COMPILER
    // --------------------------------------------------------------------------------------------
    /// Compiles the provided source code into a [Program]. The resulting program can be executed
    /// on Miden VM.
    ///
    /// # Errors
    /// Returns an error if parsing or compilation of the specified program fails.
    pub fn compile<S>(&self, source: S) -> Result<Program, AssemblyError>
    where
        S: AsRef<str>,
    {
        // parse the program into an AST
        let source = source.as_ref();
        let ProgramAst { local_procs, body } = parsers::parse_program(source)?;

        // compile all local procedures; this will add the procedures to the specified context
        let mut context = AssemblyContext::new(false);
        for proc_ast in local_procs.iter() {
            if proc_ast.is_export {
                return Err(AssemblyError::exported_proc_in_program(&proc_ast.name));
            }
            self.compile_procedure(proc_ast, &mut context)?;
        }

        // compile the program body
        let program_root = self.compile_body(body.iter(), &mut context, None)?;

        // convert the context into a call block table for the program
        let cb_table = context.into_cb_table(&self.proc_cache);

        // build and return the program
        Ok(Program::with_kernel(
            program_root,
            self.kernel.clone(),
            cb_table,
        ))
    }

    // MODULE COMPILER
    // --------------------------------------------------------------------------------------------

    /// Compiles all procedures in the specified module and adds them to the procedure cache.
    #[allow(clippy::cast_ref_to_mut)]
    fn compile_module(
        &self,
        module: &ModuleAst,
        module_path: &str,
        context: &mut AssemblyContext,
    ) -> Result<(), AssemblyError> {
        // compile all procedures in the module; once the compilation is complete, we get all
        // compiled procedures (and their combined callset) from the context
        context.begin_module(module_path)?;
        for proc_ast in module.local_procs.iter() {
            self.compile_procedure(proc_ast, context)?;
        }
        let (module_procs, module_callset) = context.complete_module();

        // add the compiled procedures to the assembler's cache. the procedures are added to the
        // cache only if:
        // - a procedure is exported from the module, or
        // - a procedure is present in the combined callset - i.e., it is an internal procedure
        //   which has been invoked via a local call instruction.
        for proc in module_procs {
            if proc.is_export() || module_callset.contains(proc.id()) {
                // TODO: figure out how to do this using interior mutability
                unsafe {
                    let mutable_self = &mut *(self as *const _ as *mut Assembler);
                    mutable_self.proc_cache.insert(*proc.id(), proc);
                }
            }
        }

        Ok(())
    }

    // PROCEDURE COMPILER
    // --------------------------------------------------------------------------------------------

    /// Compiles procedure AST into MAST and adds the complied procedure to the provided context.
    fn compile_procedure(
        &self,
        proc: &ProcedureAst,
        context: &mut AssemblyContext,
    ) -> Result<(), AssemblyError> {
        context.begin_proc(&proc.name, proc.is_export, proc.num_locals)?;

        let code_root = if proc.num_locals > 0 {
            // for procedures with locals, we need to update fmp register before and after the
            // procedure body is executed. specifically:
            // - to allocate procedure locals we need to increment fmp by the number of locals
            // - to deallocate procedure locals we need to decrement it by the same amount
            let num_locals = Felt::from(proc.num_locals);
            let wrapper = BodyWrapper {
                prologue: vec![Operation::Push(num_locals), Operation::FmpUpdate],
                epilogue: vec![Operation::Push(-num_locals), Operation::FmpUpdate],
            };
            self.compile_body(proc.body.iter(), context, Some(wrapper))?
        } else {
            self.compile_body(proc.body.iter(), context, None)?
        };

        context.complete_proc(code_root);

        Ok(())
    }

    // CODE BODY COMPILER
    // --------------------------------------------------------------------------------------------

    /// TODO: add comments
    fn compile_body<A, N>(
        &self,
        body: A,
        context: &mut AssemblyContext,
        wrapper: Option<BodyWrapper>,
    ) -> Result<CodeBlock, AssemblyError>
    where
        A: Iterator<Item = N>,
        N: Borrow<Node>,
    {
        let mut blocks: Vec<CodeBlock> = Vec::new();
        let mut span = SpanBuilder::new(wrapper);

        for node in body {
            match node.borrow() {
                Node::Instruction(instruction) => {
                    if let Some(block) =
                        self.compile_instruction(instruction, &mut span, context)?
                    {
                        span.extract_span_into(&mut blocks);
                        blocks.push(block);
                    }
                }

                Node::IfElse(t, f) => {
                    span.extract_span_into(&mut blocks);

                    let t = self.compile_body(t.iter(), context, None)?;

                    // else is an exception because it is optional; hence, will have to be replaced
                    // by noop span
                    let f = if !f.is_empty() {
                        self.compile_body(f.iter(), context, None)?
                    } else {
                        CodeBlock::new_span(vec![Operation::Noop])
                    };

                    let block = CodeBlock::new_split(t, f);

                    blocks.push(block);
                }

                Node::Repeat(n, nodes) => {
                    span.extract_span_into(&mut blocks);

                    let block = self.compile_body(nodes.iter(), context, None)?;

                    for _ in 0..*n {
                        blocks.push(block.clone());
                    }
                }

                Node::While(nodes) => {
                    span.extract_span_into(&mut blocks);

                    let block = self.compile_body(nodes.iter(), context, None)?;
                    let block = CodeBlock::new_loop(block);

                    blocks.push(block);
                }
            }
        }

        span.extract_final_span_into(&mut blocks);

        Ok(combine_blocks(blocks))
    }

    // PROCEDURE GETTER
    // --------------------------------------------------------------------------------------------
    /// Returns procedure MAST for a procedure with the specified ID.
    ///
    /// This will first check if procedure is in the assembler's cache, and if not, will attempt
    /// to find the module in which the procedure is located, compile the module, and return the
    /// compiled procedure MAST.
    fn get_imported_proc(
        &self,
        proc_id: &ProcedureId,
        context: &mut AssemblyContext,
    ) -> Result<&Procedure, AssemblyError> {
        // if the procedure is already in the procedure cache, return it
        if let Some(p) = self.proc_cache.get(proc_id) {
            return Ok(p);
        }

        // otherwise, get the module to which the procedure belongs and compile the entire module;
        // this will add all procedures exported from the module to the procedure cache
        let module = self
            .module_provider
            .get_module(proc_id)
            .ok_or_else(|| AssemblyError::imported_proc_module_not_found(proc_id))?;
        self.compile_module(&module, module.path(), context)?;

        // then, get the procedure out of the procedure cache and return; if the procedure
        // cannot be found in the cache, it is possible that the procedure was not in the
        // module returned from the module provider
        let proc = self.proc_cache.get(proc_id).ok_or_else(|| {
            AssemblyError::imported_proc_not_found_in_module(proc_id, module.path())
        })?;
        Ok(proc)
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

// BODY WRAPPER
// ================================================================================================

/// Contains a set of operations which need to be executed before and after a sequence of AST
/// nodes (i.e., code body).
struct BodyWrapper {
    prologue: Vec<Operation>,
    epilogue: Vec<Operation>,
}

// UTILITY FUNCTIONS
// ================================================================================================

pub fn combine_blocks(mut blocks: Vec<CodeBlock>) -> CodeBlock {
    debug_assert!(!blocks.is_empty(), "cannot combine empty block list");
    // merge consecutive Span blocks.
    let mut merged_blocks: Vec<CodeBlock> = Vec::with_capacity(blocks.len());
    // Keep track of all the consecutive Span blocks and are merged together when
    // there is a discontinuity.
    let mut contiguous_spans: Vec<CodeBlock> = Vec::new();

    blocks.drain(0..).for_each(|block| {
        if block.is_span() {
            contiguous_spans.push(block);
        } else {
            if !contiguous_spans.is_empty() {
                merged_blocks.push(combine_spans(&mut contiguous_spans));
            }
            merged_blocks.push(block);
        }
    });
    if !contiguous_spans.is_empty() {
        merged_blocks.push(combine_spans(&mut contiguous_spans));
    }

    // build a binary tree of blocks joining them using Join blocks
    let mut blocks = merged_blocks;
    while blocks.len() > 1 {
        let last_block = if blocks.len() % 2 == 0 {
            None
        } else {
            blocks.pop()
        };

        let mut grouped_blocks = Vec::new();
        core::mem::swap(&mut blocks, &mut grouped_blocks);
        let mut grouped_blocks = group_vector_elements::<CodeBlock, 2>(grouped_blocks);
        grouped_blocks.drain(0..).for_each(|pair| {
            blocks.push(CodeBlock::new_join(pair));
        });

        if let Some(block) = last_block {
            blocks.push(block);
        }
    }

    debug_assert!(!blocks.is_empty(), "no blocks");
    blocks.remove(0)
}

/// Returns a CodeBlock [Span] from sequence of Span blocks provided as input.
pub fn combine_spans(spans: &mut Vec<CodeBlock>) -> CodeBlock {
    if spans.len() == 1 {
        return spans.remove(0);
    }

    let mut ops = Vec::<Operation>::new();
    let mut decorators = DecoratorList::new();
    spans.drain(0..).for_each(|block| {
        if let CodeBlock::Span(span) = block {
            for decorator in span.decorators() {
                decorators.push((decorator.0 + ops.len(), decorator.1.clone()));
            }
            for batch in span.op_batches() {
                ops.extend_from_slice(batch.ops());
            }
        } else {
            panic!(
                "Codeblock was expected to be a Span Block, got {:?}.",
                block
            );
        }
    });
    CodeBlock::new_span_with_decorators(ops, decorators)
}
