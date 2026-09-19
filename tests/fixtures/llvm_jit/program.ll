; Three generated frames with real LLVM unwind tables. The host renames each
; function for each engine, so replay can distinguish retired and current code.
define void @llvm_leaf(ptr %stop) #0 {
entry:
  br label %spin

spin:
  %done = load atomic i32, ptr %stop acquire, align 4
  %running = icmp eq i32 %done, 0
  br i1 %running, label %spin, label %exit

exit:
  ret void
}

define void @llvm_caller(ptr %stop) #0 {
entry:
  notail call void @llvm_leaf(ptr %stop)
  ret void
}

define void @llvm_entry(ptr %stop) #0 {
entry:
  notail call void @llvm_caller(ptr %stop)
  ret void
}

; Omit frame pointers so the test depends on the generated unwind information.
attributes #0 = { noinline nounwind uwtable "frame-pointer"="none" "disable-tail-calls"="true" }
