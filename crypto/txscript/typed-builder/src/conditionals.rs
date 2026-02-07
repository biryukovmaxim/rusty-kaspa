use std::marker::PhantomData;

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

use crate::builder::TypedScriptBuilder;
use crate::markers::*;

// ---------------------------------------------------------------------------
// Dynamic condition (Bool on stack)
// Both branches must produce the same Stack AND same Missing.
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Bool<S>, M> {
    /// Conditional with both branches. The `Bool` on top of the stack is consumed.
    /// Both branches must produce the same stack and missing types.
    ///
    /// ```compile_fail
    /// use kaspa_txscript_typed_builder::TypedScriptBuilder;
    /// // Branches produce different Stack types — should not compile
    /// let _ = TypedScriptBuilder::new()
    ///     .add_i64(1).add_i64(1).op_num_equal()
    ///     .op_if(
    ///         |b| b.add_i64(1),       // Num<()>
    ///         |b| b.add_data(&[1]),   // Data<()> — mismatch!
    ///     );
    /// ```
    ///
    /// ```compile_fail
    /// use kaspa_txscript_typed_builder::TypedScriptBuilder;
    /// // Dynamic branches produce different Missing — should not compile
    /// let _ = TypedScriptBuilder::new()
    ///     .add_i64(1).op_not()
    ///     .op_if(
    ///         |b| b.op_add().add_i64(5).op_num_equal(),  // Missing = Num<Num<()>>
    ///         |b| b.op_equal(),                           // Missing = Data<Data<()>>
    ///     );
    /// ```
    pub fn op_if<S2, M2>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S2, M2>,
        false_branch: impl FnOnce(TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S2, M2>,
    ) -> TypedScriptBuilder<S2, M2> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let true_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");

        let false_builder = TypedScriptBuilder { builder: result.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }

    /// Conditional with only a true branch (no else). The body must be
    /// stack-neutral: it receives `(S, M)` and must return `(S, M)`.
    pub fn op_if_only(mut self, body: impl FnOnce(TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S, M> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }
}

// ---------------------------------------------------------------------------
// Missing condition (empty stack)
// The Bool comes from the sig script. Branches may have different Missing.
// ---------------------------------------------------------------------------

impl<M: AddToMissing> TypedScriptBuilder<(), M> {
    /// Conditional where the Bool is provided by the sig script.
    /// Branches may produce different Missing types, yielding `Or<M2, M3>`.
    /// The sig builder will call `choose_true()` or `choose_false()` to select.
    pub fn op_if<S2, M2, M3>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<(), M>) -> TypedScriptBuilder<S2, M2>,
        false_branch: impl FnOnce(TypedScriptBuilder<(), M>) -> TypedScriptBuilder<S2, M3>,
    ) -> TypedScriptBuilder<S2, Or<M2, M3>> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let true_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");

        let false_builder: TypedScriptBuilder<(), M> = TypedScriptBuilder { builder: result.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }

    /// Conditional with only a true branch where the Bool is from sig script.
    /// The body receives `((), M)` and returns `((), M2)`.
    /// Result Missing is `Or<M2, M>`: true-branch chose `M2`, false does nothing.
    pub fn op_if_only<M2>(
        mut self,
        body: impl FnOnce(TypedScriptBuilder<(), M>) -> TypedScriptBuilder<(), M2>,
    ) -> TypedScriptBuilder<(), Or<M2, M>> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Fixed conditions (Bool known at build time)
// ---------------------------------------------------------------------------

impl<S, M> TypedScriptBuilder<Bool<S>, M> {
    /// The Bool on top is known to be true. Only the true branch is type-checked;
    /// the dead branch receives a raw `&mut ScriptBuilder` for arbitrary bytes.
    pub fn op_if_true<S2, M2>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S2, M2>,
        dead_branch: impl FnOnce(&mut ScriptBuilder),
    ) -> TypedScriptBuilder<S2, M2> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let true_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");
        dead_branch(&mut result.builder);
        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }

    /// The Bool on top is known to be false. Only the false branch is type-checked;
    /// the dead branch receives a raw `&mut ScriptBuilder` for arbitrary bytes.
    pub fn op_if_false<S2, M2>(
        mut self,
        dead_branch: impl FnOnce(&mut ScriptBuilder),
        false_branch: impl FnOnce(TypedScriptBuilder<S, M>) -> TypedScriptBuilder<S2, M2>,
    ) -> TypedScriptBuilder<S2, M2> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");
        dead_branch(&mut self.builder);

        self.builder.add_op(OpElse).expect("script size limit exceeded");

        let false_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }

    /// The Bool is known; the entire if/else is dead code (e.g. for data embedding).
    /// The dead branch receives a raw `&mut ScriptBuilder`.
    pub fn op_if_dead(mut self, dead_branch: impl FnOnce(&mut ScriptBuilder)) -> TypedScriptBuilder<S, M> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");
        dead_branch(&mut self.builder);
        self.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}
