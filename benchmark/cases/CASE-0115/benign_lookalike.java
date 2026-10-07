public class VerbMethodMapper {

    public interface Mapping {
        void setMethod(String method);
    }

    /**
     * Same "hand a method name to mapping.setMethod(...)" shape, but the name
     * comes from a fixed developer-written table keyed by the HTTP verb, so
     * request text never becomes the method name.
     */
    static String methodFor(String httpVerb) {
        switch (httpVerb) {
            case "GET":
                return "index";
            case "POST":
                return "create";
            case "PUT":
                return "update";
            case "DELETE":
                return "destroy";
            default:
                return null;
        }
    }

    public void apply(Mapping mapping, String httpVerb) {
        String actionMethod = methodFor(httpVerb);
        mapping.setMethod(actionMethod);
    }
}
