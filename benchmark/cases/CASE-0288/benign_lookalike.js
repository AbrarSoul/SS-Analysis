// Standalone example of the same shape: substitute a label into a message
// that is written with .text() (never parsed as HTML), so markup in the
// label stays inert text.
function showFieldHint(container, label)
{
    var message = "Please fill in _XXX_".replace("_XXX_", label);
    $(container).find(".hint").text(message);
}
