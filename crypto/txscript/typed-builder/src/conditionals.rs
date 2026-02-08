use std::marker::PhantomData;

use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

use crate::builder::TypedScriptBuilder;
use crate::markers::*;

// ---------------------------------------------------------------------------
// Dynamic condition (Bool on stack)
// Both branches must produce the same Stack, Missing, AND AltStack.
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Bool<S>, M, A> {
    /// Conditional with both branches. The `Bool` on top of the stack is consumed.
    /// Both branches must produce the same stack, missing, and alt stack types.
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
    pub fn op_if<S2, M2, A2>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
        false_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
    ) -> TypedScriptBuilder<S2, M2, A2> {
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
    /// stack-neutral: it receives `(S, M, A)` and must return `(S, M, A)`.
    pub fn op_if_only(
        mut self,
        body: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S, M, A>,
    ) -> TypedScriptBuilder<S, M, A> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }

    /// OpNotIf: the **inverse** of OpIf. The first closure (`false_branch`)
    /// runs when the Bool is **false**; the second (`true_branch`) when **true**.
    /// Both branches must produce the same stack, missing, and alt stack types.
    pub fn op_not_if<S2, M2, A2>(
        mut self,
        false_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
        true_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
    ) -> TypedScriptBuilder<S2, M2, A2> {
        self.builder.add_op(OpNotIf).expect("script size limit exceeded");

        let false_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");

        let true_builder = TypedScriptBuilder { builder: result.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }

    /// OpNotIf with only a false branch (no else). The body runs when the Bool
    /// is **false** and must be stack-neutral.
    pub fn op_not_if_only(
        mut self,
        body: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S, M, A>,
    ) -> TypedScriptBuilder<S, M, A> {
        self.builder.add_op(OpNotIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        result
    }
}

// ---------------------------------------------------------------------------
// Missing condition (empty stack)
// The Bool comes from the sig script. Branches may have different Missing.
// Both branches must produce the same AltStack.
// ---------------------------------------------------------------------------

impl<M: AddToMissing, A> TypedScriptBuilder<(), M, A> {
    /// Conditional where the Bool is provided by the sig script.
    /// Branches may produce different Missing types, yielding `Or<M2, M3>`.
    /// The sig builder will call `choose_true()` or `choose_false()` to select.
    /// Both branches must produce the same AltStack type.
    pub fn op_if<S2, M2, M3, A2>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<S2, M2, A2>,
        false_branch: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<S2, M3, A2>,
    ) -> TypedScriptBuilder<S2, Or<M2, M3>, A2> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let true_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");

        let false_builder: TypedScriptBuilder<(), M, A> = TypedScriptBuilder { builder: result.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }

    /// Conditional with only a true branch where the Bool is from sig script.
    /// The body receives `((), M, A)` and returns `((), M2, A2)`.
    /// Result Missing is `Or<M2, M>`: true-branch chose `M2`, false does nothing.
    /// Both branches must produce the same AltStack type — since the false branch
    /// does nothing, A2 must equal A.
    pub fn op_if_only<M2>(
        mut self,
        body: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<(), M2, A>,
    ) -> TypedScriptBuilder<(), Or<M2, M>, A> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }

    /// OpNotIf where the Bool is provided by the sig script.
    /// The first closure (`false_branch`) runs when Bool is false;
    /// the second (`true_branch`) when true.
    /// Branches may produce different Missing types, yielding `Or<M3, M2>`:
    /// `Or<true_missing, false_missing>` to match the `Or<T, F>` convention.
    pub fn op_not_if<S2, M2, M3, A2>(
        mut self,
        false_branch: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<S2, M2, A2>,
        true_branch: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<S2, M3, A2>,
    ) -> TypedScriptBuilder<S2, Or<M3, M2>, A2> {
        self.builder.add_op(OpNotIf).expect("script size limit exceeded");

        let false_builder = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = false_branch(false_builder);

        result.builder.add_op(OpElse).expect("script size limit exceeded");

        let true_builder: TypedScriptBuilder<(), M, A> = TypedScriptBuilder { builder: result.builder, _phantom: PhantomData };
        let mut result = true_branch(true_builder);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }

    /// OpNotIf with only a false branch where the Bool is from sig script.
    /// The body runs when Bool is false. Result Missing is `Or<M, M2>`:
    /// true branch does nothing (`M` unchanged), false branch produces `M2`.
    pub fn op_not_if_only<M2>(
        mut self,
        body: impl FnOnce(TypedScriptBuilder<(), M, A>) -> TypedScriptBuilder<(), M2, A>,
    ) -> TypedScriptBuilder<(), Or<M, M2>, A> {
        self.builder.add_op(OpNotIf).expect("script size limit exceeded");

        let inner = TypedScriptBuilder { builder: self.builder, _phantom: PhantomData };
        let mut result = body(inner);

        result.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: result.builder, _phantom: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Fixed conditions (Bool known at build time)
// ---------------------------------------------------------------------------

impl<S, M, A> TypedScriptBuilder<Bool<S>, M, A> {
    /// The Bool on top is known to be true. Only the true branch is type-checked;
    /// the dead branch receives a raw `&mut ScriptBuilder` for arbitrary bytes.
    pub fn op_if_true<S2, M2, A2>(
        mut self,
        true_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
        dead_branch: impl FnOnce(&mut ScriptBuilder),
    ) -> TypedScriptBuilder<S2, M2, A2> {
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
    pub fn op_if_false<S2, M2, A2>(
        mut self,
        dead_branch: impl FnOnce(&mut ScriptBuilder),
        false_branch: impl FnOnce(TypedScriptBuilder<S, M, A>) -> TypedScriptBuilder<S2, M2, A2>,
    ) -> TypedScriptBuilder<S2, M2, A2> {
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
    pub fn op_if_dead(mut self, dead_branch: impl FnOnce(&mut ScriptBuilder)) -> TypedScriptBuilder<S, M, A> {
        self.builder.add_op(OpIf).expect("script size limit exceeded");
        dead_branch(&mut self.builder);
        self.builder.add_op(OpEndIf).expect("script size limit exceeded");
        TypedScriptBuilder { builder: self.builder, _phantom: PhantomData }
    }
}
