package io.dataease.dto.datasource;

import io.dataease.plugins.datasource.entity.JdbcConfiguration;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

@Getter
@Setter
public class MysqlConfiguration extends JdbcConfiguration {

    private String driver = "com.mysql.jdbc.Driver";
    private String extraParams = "characterEncoding=UTF-8&connectTimeout=5000&useSSL=false&allowPublicKeyRetrieval=true&zeroDateTimeBehavior=convertToNull";

    public String getJdbc() {
        if(StringUtils.isEmpty(extraParams.trim())){
            return "jdbc:mysql://HOSTNAME:PORT/DATABASE"
                    .replace("HOSTNAME", getHost().trim())
                    .replace("PORT", getPort().toString().trim())
                    .replace("DATABASE", getDataBase().trim());
        }else {
            assertSafeExtraParams(getExtraParams().trim());
            return "jdbc:mysql://HOSTNAME:PORT/DATABASE?EXTRA_PARAMS"
                    .replace("HOSTNAME", getHost().trim())
                    .replace("PORT", getPort().toString().trim())
                    .replace("DATABASE", getDataBase().trim())
                    .replace("EXTRA_PARAMS", getExtraParams().trim());
        }
    }

    private static void assertSafeExtraParams(String params) {
        java.util.Set<String> allowed = new java.util.HashSet<>(java.util.Arrays.asList(
                "characterEncoding", "connectTimeout", "socketTimeout", "useSSL", "allowPublicKeyRetrieval",
                "zeroDateTimeBehavior", "serverTimezone", "useUnicode", "autoReconnect", "tinyInt1isBit"));
        if (!params.matches("[A-Za-z0-9_.\\-=&/:]*")) {
            throw new RuntimeException("Illegal characters in extra parameters");
        }
        for (String pair : params.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            if (!allowed.contains(name)) {
                throw new RuntimeException("Illegal parameter: " + name);
            }
        }
    }
}