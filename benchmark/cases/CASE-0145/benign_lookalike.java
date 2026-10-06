import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

class TagCounter {
    private final SQLiteDatabase db;

    TagCounter(SQLiteDatabase db) {
        this.db = db;
    }

    /**
     * Same string-concatenated WHERE clause as a tag lookup, but the only
     * concatenated pieces are developer-fixed column names and a validated
     * numeric id; no user-supplied text ever enters the SQL.
     */
    int countForAccount(long accountId) {
        Cursor cursor = db.query("tags", new String[]{"_id"},
                "id_account" + " = " + Long.valueOf(accountId), null, null, null, null);
        try {
            return cursor.getCount();
        } finally {
            cursor.close();
        }
    }
}
