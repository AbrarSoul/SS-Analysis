package org.lemsml.jlems.io.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class SafeJarUnpacker {

    public static void unpackJar(File fjar, File fout) throws IOException {
        String outCanonical = fout.getCanonicalPath() + File.separator;
        JarFile jf = new JarFile(fjar);
        Enumeration<JarEntry> en = jf.entries();

        while (en.hasMoreElements()) {
            JarEntry je = en.nextElement();
            File f = new File(fout, je.getName());
            String candidateCanonical = f.getCanonicalPath();
            if (!candidateCanonical.startsWith(outCanonical)) {
                throw new IOException("Entry is outside of the target dir: " + je.getName());
            }
            if (je.isDirectory()) {
                f.mkdirs();
                continue;
            }
            if (f.getPath().indexOf("META-INF") >= 0) {
                continue;
            }
            f.getParentFile().mkdirs();
            java.io.InputStream is = jf.getInputStream(je);
            FileOutputStream fos = new FileOutputStream(f);
            while (is.available() > 0) {
                fos.write(is.read());
            }
            fos.close();
            is.close();
        }
    }
}
