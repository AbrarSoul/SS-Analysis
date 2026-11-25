import cz.speedy11.mcrpx.common.extraction.ExtractTaskListener;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Calls <class>.<method>(zip, dest, listener) by reflection, so samples with renamed classes or methods need no edits. */
public class Harness {
  public static void main(String[] a) throws Exception {
    ExtractTaskListener l = new ExtractTaskListener() {
      public void bytesTotal(int b) {} public void fileProcessed(int b) {} public void taskCompleted() {}
      public void onError(Exception e) { System.out.println("    listener error: " + e); }
      public void onMessage(String m) { System.out.println("    log: " + m); } };
    Method m = Class.forName(a[2]).getMethod(a[3], File.class, File.class, ExtractTaskListener.class);
    try { m.invoke(null, new File(a[0]), new File(a[1]), l); }
    catch (InvocationTargetException e) { System.out.println("    threw: " + e.getCause()); }
  }
}
