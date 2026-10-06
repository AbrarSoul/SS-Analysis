import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class FlatZipExtractor {

   /**
    * Same ZipInputStream loop as processZipStream, but every entry is written
    * to a file named by its bare file name (new File(name).getName()), so no
    * entry can carry a path out of the target directory.
    */
   public static void extractFlat(File dir, InputStream in) throws IOException
   {
      ZipInputStream zip = new ZipInputStream(in);
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null)
      {
         if (entry.isDirectory())
         {
            continue;
         }
         try (FileOutputStream out = new FileOutputStream(new File(dir, new File(entry.getName()).getName())))
         {
            byte[] bytes = new byte[1024];
            int length;
            while ((length = zip.read(bytes)) >= 0)
            {
               out.write(bytes, 0, length);
            }
         }
      }
   }
}
