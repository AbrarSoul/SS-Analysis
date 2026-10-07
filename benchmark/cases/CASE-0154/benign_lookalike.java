import cn.hutool.core.util.IdUtil;
import cn.hutool.poi.excel.BigExcelWriter;
import cn.hutool.poi.excel.ExcelUtil;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StaticReport {

    /**
     * Same BigExcelWriter.write(list, true) export shape, but every cell is a
     * developer-written literal, so no stored user text can start with a
     * formula character.
     */
    public static File writeHeaderTemplate(String dir) {
        File file = new File(dir + IdUtil.fastSimpleUUID() + ".xlsx");
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("Name", "Example item");
        row.put("Total", 0);
        rows.add(row);
        BigExcelWriter writer = ExcelUtil.getBigWriter(file);
        writer.write(rows, true);
        writer.close();
        return file;
    }
}
