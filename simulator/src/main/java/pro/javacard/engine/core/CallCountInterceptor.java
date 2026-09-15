// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import com.licel.jcardsim.base.Simulator;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.Arrays;
import java.util.stream.Collectors;

final class CallCountInterceptor extends ClassVisitor {
    private static final String SIMULATOR = Type.getInternalName(Simulator.class);

    private final IsolatingClassReloader loader;
    private String type;

    CallCountInterceptor(ClassVisitor classVisitor, IsolatingClassReloader loader) {
        super(Opcodes.ASM9, classVisitor);
        this.loader = loader;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        super.visit(version, access, name, signature, superName, interfaces);
        this.type = name;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        String self = label(type, name, descriptor);
        return new MethodVisitor(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions)) {
            @Override
            public void visitCode() {
                super.visitCode();
                count(self);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String method, String desc, boolean isInterface) {
                String callee = callee(owner, method, desc);
                if (callee != null) {
                    count(callee);
                }
                super.visitMethodInsn(opcode, owner, method, desc, isInterface);
            }

            private void count(String label) {
                super.visitLdcInsn(label);
                super.visitMethodInsn(Opcodes.INVOKESTATIC, SIMULATOR, "callcount", "(Ljava/lang/String;)V", false);
            }
        };
    }

    private String callee(String owner, String method, String desc) {
        String declaring = owner;
        while (loader.isolates(declaring)) {
            ClassReader reader = BytecodeUtils.reader(loader, declaring);
            if (declares(reader, method, desc)) {
                return null;
            }
            declaring = reader.getSuperName();
        }
        return label(declaring, method, desc);
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

    private static String label(String owner, String method, String desc) {
        String args = Arrays.stream(Type.getArgumentTypes(desc)).map(t -> simple(t.getClassName())).collect(Collectors.joining(","));
        return simple(Type.getObjectType(owner).getClassName()) + "." + method + "(" + args + ")";
    }

    private static String simple(String className) {
        return className.substring(className.lastIndexOf('.') + 1);
    }
}
