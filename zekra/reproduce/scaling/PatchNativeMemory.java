import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.*;
import jdk.internal.org.objectweb.asm.*;

/** Research-only repair of native-field SmartMemory metadata, in an isolated jar. */
public final class PatchNativeMemory implements Opcodes {
  static final String OWNER = "backend/auxTypes/SmartMemory";
  static final String ENTRY = OWNER + ".class";
  static final String WIDTH = "zkcfaNativeMemoryChunkWidth";
  static final String WIDTH_DESC = "(L" + OWNER + ";)I";
  static void emitNativeWidth(MethodVisitor mv) {
    Label ordinary = new Label();
    mv.visitCode();
    mv.visitVarInsn(ALOAD, 0); mv.visitFieldInsn(GETFIELD, OWNER, "typeClass", "Ljava/lang/Class;");
    mv.visitLdcInsn(Type.getObjectType("backend/auxTypes/FieldElement"));
    mv.visitJumpInsn(IF_ACMPNE, ordinary);
    mv.visitTypeInsn(NEW,"java/math/BigInteger"); mv.visitInsn(DUP);
    mv.visitVarInsn(ALOAD,0); mv.visitFieldInsn(GETFIELD,OWNER,"typeArgs","[Ljava/lang/Object;");
    mv.visitInsn(ICONST_0); mv.visitInsn(AALOAD); mv.visitTypeInsn(CHECKCAST,"java/lang/String");
    mv.visitMethodInsn(INVOKESPECIAL,"java/math/BigInteger","<init>","(Ljava/lang/String;)V",false);
    mv.visitMethodInsn(INVOKESTATIC,"backend/config/Config","getFiniteFieldModulus","()Ljava/math/BigInteger;",false);
    mv.visitMethodInsn(INVOKEVIRTUAL,"java/math/BigInteger","equals","(Ljava/lang/Object;)Z",false);
    mv.visitJumpInsn(IFEQ,ordinary);
    mv.visitMethodInsn(INVOKESTATIC,"backend/config/Config","getNumBitsFiniteFieldModulus","()I",false);
    mv.visitInsn(IRETURN); mv.visitLabel(ordinary);
    mv.visitFieldInsn(GETSTATIC,"backend/auxTypes/UnsignedInteger","BITWIDTH_PER_CHUNK","I");
    mv.visitInsn(IRETURN); mv.visitMaxs(0,0); mv.visitEnd();
  }
  static String hash(byte[] b) throws Exception {
    StringBuilder s = new StringBuilder();
    for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) s.append(String.format("%02x", x));
    return s.toString();
  }
  public static void main(String[] args) throws Exception {
    Path src = Paths.get(args[0]), dst = Paths.get(args[1]);
    int[] methods = {0}, witnessCalls = {0};
    try (JarFile jar = new JarFile(src.toFile()); JarOutputStream out = new JarOutputStream(Files.newOutputStream(dst))) {
      for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();) {
        JarEntry entry = e.nextElement();
        byte[] bytes = jar.getInputStream(entry).readAllBytes();
        if (entry.getName().equals(ENTRY) || entry.getName().matches("backend/auxTypes/SmartMemory\\$[234]\\.class")) {
          final ClassReader reader = new ClassReader(bytes);
          final String className = reader.getClassName();
          final ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
          reader.accept(new ClassVisitor(ASM5, writer) {
            @Override public MethodVisitor visitMethod(int a, String n, String d, String sig, String[] exceptions) {
              MethodVisitor base = super.visitMethod(a,n,d,sig,exceptions);
              if (!className.equals(OWNER) && n.equals("evaluate")) {
                return new MethodVisitor(ASM5,base) {
                  @Override public void visitMethodInsn(int op,String owner,String name,String desc,boolean itf) {
                    if (owner.equals("backend/eval/CircuitEvaluator") && name.equals("setWireValue")
                        && desc.equals("(Lbackend/auxTypes/PackedValue;Ljava/math/BigInteger;II)V")) {
                      // Replace only the chunk-width argument of memory DATA writes.
                      // The existing value, destination, and total bit width remain.
                      super.visitInsn(POP); super.visitVarInsn(ALOAD,0);
                      super.visitFieldInsn(GETFIELD,className,"this$0","L"+OWNER+";");
                      super.visitMethodInsn(INVOKESTATIC,OWNER,WIDTH,WIDTH_DESC,false);
                      witnessCalls[0]++;
                    }
                    super.visitMethodInsn(op,owner,name,desc,itf);
                  }
                };
              }
              if (!n.equals("getElementSize") || !d.equals("()[I")) return base;
              methods[0]++;
              return new MethodVisitor(ASM5, base) {
                @Override public void visitCode() {
                  super.visitCode();
                  Label original = new Label();
                  // Native FieldElement has one full-width packed wire, not 32-bit chunks.
                  visitVarInsn(ALOAD, 0);
                  visitFieldInsn(GETFIELD, OWNER, "typeClass", "Ljava/lang/Class;");
                  visitLdcInsn(Type.getObjectType("backend/auxTypes/FieldElement"));
                  visitJumpInsn(IF_ACMPNE, original);
                  visitTypeInsn(NEW, "java/math/BigInteger"); visitInsn(DUP);
                  visitVarInsn(ALOAD, 0);
                  visitFieldInsn(GETFIELD, OWNER, "typeArgs", "[Ljava/lang/Object;");
                  visitInsn(ICONST_0); visitInsn(AALOAD); visitTypeInsn(CHECKCAST, "java/lang/String");
                  visitMethodInsn(INVOKESPECIAL, "java/math/BigInteger", "<init>", "(Ljava/lang/String;)V", false);
                  visitMethodInsn(INVOKESTATIC, "backend/config/Config", "getFiniteFieldModulus", "()Ljava/math/BigInteger;", false);
                  visitMethodInsn(INVOKEVIRTUAL, "java/math/BigInteger", "equals", "(Ljava/lang/Object;)Z", false);
                  visitJumpInsn(IFEQ, original);
                  visitInsn(ICONST_1); visitIntInsn(NEWARRAY, T_INT); visitInsn(DUP); visitInsn(ICONST_0);
                  visitMethodInsn(INVOKESTATIC, "backend/config/Config", "getNumBitsFiniteFieldModulus", "()I", false);
                  visitInsn(IASTORE); visitInsn(ARETURN);
                  visitLabel(original);
                }
              };
            }
            @Override public void visitEnd() {
              if (className.equals(OWNER)) emitNativeWidth(super.visitMethod(ACC_STATIC,WIDTH,WIDTH_DESC,null,null));
              super.visitEnd();
            }
          }, 0);
          bytes = writer.toByteArray();
        }
        JarEntry copy = new JarEntry(entry.getName()); copy.setTime(0L);
        out.putNextEntry(copy); out.write(bytes); out.closeEntry();
      }
    }
    if (methods[0] != 1 || witnessCalls[0] != 7)
      throw new IllegalStateException("Expected one getElementSize method and seven memory-data witness writes");
    System.out.println("input_sha256=" + hash(Files.readAllBytes(src)));
    System.out.println("output_sha256=" + hash(Files.readAllBytes(dst)));
    System.out.println("patch=native-modulus FieldElement getElementSize returns one full-width limb; seven memory-data witness writes use native width; original other-type fallbacks retained");
  }
}
