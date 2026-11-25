    private List<GHPoint> getPointsFromRequest(HttpServletRequest httpServletRequest, String profile) {

        String url_renamed = httpServletRequest.getRequestURI();
        url_renamed = url_renamed.replaceFirst("/navigate/directions/v5/gh/" + profile + "/", "");
        url_renamed = url_renamed.replaceAll("\\?[*]", "");

        String[] pointStrings = url_renamed.split(";");

        List<GHPoint> points = new ArrayList<>(pointStrings.length);
        for (int i = 0; i < pointStrings.length; i++) {
            points.add(GHPoint.fromStringLonLat(pointStrings[i]));
        }

        return points;
    }