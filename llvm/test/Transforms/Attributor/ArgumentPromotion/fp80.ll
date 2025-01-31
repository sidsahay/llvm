; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --check-attributes --check-globals
; RUN: opt -aa-pipeline=basic-aa -passes=attributor -attributor-manifest-internal  -attributor-max-iterations-verify -attributor-annotate-decl-cs -attributor-max-iterations=2 -S < %s | FileCheck %s --check-prefixes=CHECK,TUNIT
; RUN: opt -aa-pipeline=basic-aa -passes=attributor-cgscc -attributor-manifest-internal  -attributor-annotate-decl-cs -S < %s | FileCheck %s --check-prefixes=CHECK,CGSCC

target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%union.u = type { x86_fp80 }
%struct.s = type { double, i16, i8, [5 x i8] }

@b = internal global %struct.s { double 3.14, i16 9439, i8 25, [5 x i8] undef }, align 16

%struct.Foo = type { i32, i64 }
@a = internal global %struct.Foo { i32 1, i64 2 }, align 8

;.
; CHECK: @[[B:[a-zA-Z0-9_$"\\.-]+]] = internal global [[STRUCT_S:%.*]] { double 3.140000e+00, i16 9439, i8 25, [5 x i8] undef }, align 16
; CHECK: @[[A:[a-zA-Z0-9_$"\\.-]+]] = internal global [[STRUCT_FOO:%.*]] { i32 1, i64 2 }, align 8
;.
define void @run() {
;
; TUNIT: Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
; TUNIT-LABEL: define {{[^@]+}}@run
; TUNIT-SAME: () #[[ATTR0:[0-9]+]] {
; TUNIT-NEXT:  entry:
; TUNIT-NEXT:    unreachable
;
; CGSCC: Function Attrs: mustprogress nofree nosync nounwind willreturn memory(none)
; CGSCC-LABEL: define {{[^@]+}}@run
; CGSCC-SAME: () #[[ATTR0:[0-9]+]] {
; CGSCC-NEXT:  entry:
; CGSCC-NEXT:    unreachable
;
entry:
  tail call i8 @UseLongDoubleUnsafely(ptr byval(%union.u) align 16 @b)
  tail call x86_fp80 @UseLongDoubleSafely(ptr byval(%union.u) align 16 @b)
  call i64 @AccessPaddingOfStruct(ptr byval(%struct.Foo) @a)
  call i64 @CaptureAStruct(ptr byval(%struct.Foo) @a)
  ret void
}

define internal i8 @UseLongDoubleUnsafely(ptr byval(%union.u) align 16 %arg) {
; CGSCC: Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
; CGSCC-LABEL: define {{[^@]+}}@UseLongDoubleUnsafely
; CGSCC-SAME: () #[[ATTR1:[0-9]+]] {
; CGSCC-NEXT:  entry:
; CGSCC-NEXT:    ret i8 undef
;
entry:
  %bitcast = bitcast ptr %arg to ptr
  %gep = getelementptr inbounds %struct.s, ptr %bitcast, i64 0, i32 2
  %result = load i8, ptr %gep
  ret i8 %result
}

define internal x86_fp80 @UseLongDoubleSafely(ptr byval(%union.u) align 16 %arg) {
; CGSCC: Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
; CGSCC-LABEL: define {{[^@]+}}@UseLongDoubleSafely
; CGSCC-SAME: () #[[ATTR1]] {
; CGSCC-NEXT:    ret x86_fp80 undef
;
  %gep = getelementptr inbounds %union.u, ptr %arg, i64 0, i32 0
  %fp80 = load x86_fp80, ptr %gep
  ret x86_fp80 %fp80
}

define internal i64 @AccessPaddingOfStruct(ptr byval(%struct.Foo) %a) {
; CGSCC: Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
; CGSCC-LABEL: define {{[^@]+}}@AccessPaddingOfStruct
; CGSCC-SAME: () #[[ATTR1]] {
; CGSCC-NEXT:    ret i64 undef
;
  %p = bitcast ptr %a to ptr
  %v = load i64, ptr %p
  ret i64 %v
}

define internal i64 @CaptureAStruct(ptr byval(%struct.Foo) %a) {
; CGSCC: Function Attrs: nofree norecurse noreturn nosync nounwind memory(none)
; CGSCC-LABEL: define {{[^@]+}}@CaptureAStruct
; CGSCC-SAME: (i32 [[TMP0:%.*]], i64 [[TMP1:%.*]]) #[[ATTR2:[0-9]+]] {
; CGSCC-NEXT:  entry:
; CGSCC-NEXT:    [[A_PRIV:%.*]] = alloca [[STRUCT_FOO:%.*]], align 8
; CGSCC-NEXT:    store i32 [[TMP0]], ptr [[A_PRIV]], align 4
; CGSCC-NEXT:    [[A_PRIV_0_1:%.*]] = getelementptr [[STRUCT_FOO]], ptr [[A_PRIV]], i64 0, i32 1
; CGSCC-NEXT:    store i64 [[TMP1]], ptr [[A_PRIV_0_1]], align 8
; CGSCC-NEXT:    [[A_PTR:%.*]] = alloca ptr, align 8
; CGSCC-NEXT:    br label [[LOOP:%.*]]
; CGSCC:       loop:
; CGSCC-NEXT:    [[PHI:%.*]] = phi ptr [ null, [[ENTRY:%.*]] ], [ [[A_PRIV]], [[LOOP]] ]
; CGSCC-NEXT:    [[TMP2:%.*]] = phi ptr [ [[A_PRIV]], [[ENTRY]] ], [ [[TMP2]], [[LOOP]] ]
; CGSCC-NEXT:    br label [[LOOP]]
;
entry:
  %a_ptr = alloca ptr
  br label %loop

loop:
  %phi = phi ptr [ null, %entry ], [ %gep, %loop ]
  %0   = phi ptr [ %a, %entry ],   [ %0, %loop ]
  store ptr %phi, ptr %a_ptr
  %gep = getelementptr %struct.Foo, ptr %a, i64 0
  br label %loop
}
;.
; TUNIT: attributes #[[ATTR0]] = { mustprogress nofree norecurse nosync nounwind willreturn memory(none) }
;.
; CGSCC: attributes #[[ATTR0]] = { mustprogress nofree nosync nounwind willreturn memory(none) }
; CGSCC: attributes #[[ATTR1]] = { mustprogress nofree norecurse nosync nounwind willreturn memory(none) }
; CGSCC: attributes #[[ATTR2]] = { nofree norecurse noreturn nosync nounwind memory(none) }
;.
;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; CHECK: {{.*}}
