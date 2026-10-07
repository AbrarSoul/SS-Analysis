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
        String base = "jdbc:mysql://" + getHost().trim() + ":" + getPort().toString().trim() + "/" + getDataBase().trim();
        if (StringUtils.isEmpty(extraParams.trim())) {
            return base;
        }
        return base + "?" + getExtraParams().trim();
    }
}