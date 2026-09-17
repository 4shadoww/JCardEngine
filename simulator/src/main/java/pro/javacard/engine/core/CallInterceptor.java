// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

import java.util.Arrays;
import java.util.stream.Collectors;

final class CallInterceptor extends ClassVisitor {
    private final IsolatingClassReloader loader;
    private String type;
    private String parent;

    CallInterceptor(ClassVisitor classVisitor, IsolatingClassReloader loader) {
        super(Opcodes.ASM9, classVisitor);
        this.loader = loader;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        super.visit(version, access, name, signature, superName, interfaces);
        this.type = name;
        this.parent = superName;
        var node = new ClassNode();
        BytecodeUtils.reader(loader, name).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (var method : node.methods) {
            long size = Arrays.stream(method.instructions.toArray()).filter(insn -> insn.getOpcode() >= 0).count();
            loader.sizes.put(label(name, method.name, method.desc, (method.access & Opcodes.ACC_STATIC) != 0), (int) size);
        }
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        String self = label(type, name, descriptor, (access & Opcodes.ACC_STATIC) != 0);
        String superctor = name.equals("<init>") ? parent : null;
        return new MethodVisitor(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions)) {
            @Override
            public void visitCode() {
                super.visitCode();
                BytecodeUtils.callback(mv, "__call", self);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String method, String desc, boolean isInterface) {
                String callee = owner.equals(superctor) && method.equals("<init>") ? null : callee(owner, method, desc, opcode == Opcodes.INVOKESTATIC);
                if (callee != null) {
                    BytecodeUtils.callback(mv, "__call", callee);
                }
                super.visitMethodInsn(opcode, owner, method, desc, isInterface);
            }
        };
    }

    private String callee(String owner, String method, String desc, boolean isstatic) {
        String declaring = owner;
        while (loader.isolates(declaring)) {
            ClassReader reader = BytecodeUtils.reader(loader, declaring);
            if (declares(reader, method, desc) || inherits(reader, method, desc)) {
                return null;
            }
            if ((reader.getAccess() & Opcodes.ACC_INTERFACE) != 0) {
                break;
            }
            declaring = reader.getSuperName();
        }
        return label(declaring, method, desc, isstatic);
    }

    private boolean inherits(ClassReader reader, String method, String desc) {
        for (String iface : reader.getInterfaces()) {
            if (loader.isolates(iface)) {
                ClassReader parent = BytecodeUtils.reader(loader, iface);
                if (declares(parent, method, desc) || inherits(parent, method, desc)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean declares(ClassReader reader, String method, String desc) {
        var found = new boolean[1];
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                found[0] |= name.equals(method) && descriptor.equals(desc);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return found[0];
    }

    private static String label(String owner, String method, String desc, boolean isstatic) {
        String args = Arrays.stream(Type.getArgumentTypes(desc)).map(t -> simple(t.getClassName())).collect(Collectors.joining(","));
        String type = simple(Type.getObjectType(owner).getClassName());
        String name = method.equals("<init>") ? "new " + type : type + (isstatic ? "." : "#") + method;
        return name + "(" + args + ")";
    }

    private static String simple(String className) {
        return className.substring(className.lastIndexOf('.') + 1);
    }
}
