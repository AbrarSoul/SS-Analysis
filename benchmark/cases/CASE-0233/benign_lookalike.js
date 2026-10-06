// Standalone example of the same shape: the role of a newly created account
// is derived from server-side state (how many accounts exist), never from a
// client-controlled header.
function isFirstAccount(userCount) {
    return userCount === 0;
}

function roleForNewAccount(userCount) {
    return isFirstAccount(userCount) ? 'owner' : 'member';
}

module.exports = { roleForNewAccount };
