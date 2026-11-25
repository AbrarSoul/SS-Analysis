    private List<GHPoint> getPointsFromRequest(HttpServletRequest httpServletRequest, String profile) {
        String url_renamed = httpServletRequest.getRequestURI();
        String urlStart = "/navigate/directions/v5/gh/" + profile + "/";
        if (!url_renamed.startsWith(urlStart)) throw new IllegalArgumentException("Incorrect URL " + url_renamed);
        url_renamed = url_renamed.substring(urlStart.length());
        String[] pointStrings = url_renamed.split(";");
        List<GHPoint> points = new ArrayList<>(pointStrings.length);
        for (int i = 0; i < pointStrings.length; i++) {
            points.add(GHPoint.fromStringLonLat(pointStrings[i]));
        }

        return points;
    }