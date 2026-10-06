package com.suisung.shopsuite.pt.service.impl;

/**
 * Standalone example of the same shape: pick a display sort label for a UI
 * dropdown from a fixed enum, never building any SQL from it.
 */
public class SortLabelPicker {

    public enum Order { NEWEST, PRICE_ASC, PRICE_DESC }

    public static String label(Order order) {
        return switch (order) {
            case NEWEST -> "Newest first";
            case PRICE_ASC -> "Price: low to high";
            case PRICE_DESC -> "Price: high to low";
        };
    }
}
