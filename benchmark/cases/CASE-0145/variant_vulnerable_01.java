package com.dimtion.shaarlier;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by dimtion on 12/05/2015.
 * Interface between the table TAGS and the JAVA objects
 */
class TagsSource {
    private final String[] allColumns = {MySQLiteHelper.TAGS_COLUMN_ID,
            MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT,
            MySQLiteHelper.TAGS_COLUMN_TAG};
    private final MySQLiteHelper dbHelper;
    private SQLiteDatabase db;

    public TagsSource(Context context) {
        dbHelper = new MySQLiteHelper(context);
    }

    public void rOpen() throws SQLException {
        db = dbHelper.getReadableDatabase();
    }

    public void wOpen() throws SQLException {
        db = dbHelper.getWritableDatabase();
    }

    public void close() {
        dbHelper.close();
    }

    public List<Tag> getAllTags() {
        List<Tag> tags = new ArrayList<>();

        Cursor cursor = db.query(MySQLiteHelper.TABLE_TAGS, allColumns, null, null, null, null, null);
        cursor.moveToFirst();
        while (!cursor.isAfterLast()) {
            Tag account = cursorToTag(cursor);
            tags.add(account);
            cursor.moveToNext();
        }

        cursor.close();
        return tags;
    }

    public Tag addTag(ShaarliAccount account, String tagText) {
        Tag newTag = new Tag();
        newTag.setMasterAccount(account);
        newTag.setValue(tagText.trim());

        ContentValues row = new ContentValues();
        row.put(MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT, account.getId());
        row.put(MySQLiteHelper.TAGS_COLUMN_TAG, newTag.getValue());

        // If existing, do nothing :
        Cursor existing = db.query(MySQLiteHelper.TABLE_TAGS, allColumns,
                MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT + " = " + newTag.getMasterAccountId() + " AND " +
                        MySQLiteHelper.TAGS_COLUMN_TAG + " = '" + newTag.getValue() + "'",
                null, null, null, null);
        try {
            existing.moveToFirst();
            if (existing.isAfterLast()) {
                long newId = db.insert(MySQLiteHelper.TABLE_TAGS, null, row);
                newTag.setId(newId);
                return newTag;
            } else {
                newTag = cursorToTag(existing);
            }
        } catch (Exception ex){
            newTag = null;
        } finally {
            existing.close();
        }
        return newTag;
    }

    private Tag cursorToTag(Cursor cursor) {  // If necessary (later), load the full account in the tag
        Tag tag = new Tag();
        tag.setId(cursor.getLong(0));
        tag.setMasterAccountId(cursor.getLong(1));
        tag.setValue(cursor.getString(2));
        return tag;
    }

    private void deleteAllTags() {
        db.delete(MySQLiteHelper.TABLE_TAGS, null, null);
    }
}
