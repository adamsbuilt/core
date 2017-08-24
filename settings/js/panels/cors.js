function removeDomain(id, token, confirmText, callback) {
    OC.dialogs.confirm(
        t('settings', confirmText), t('settings','CORS'),
        function (result) {
            if (result) {
                $.ajax({
                    type: 'DELETE',
                    url: OC.generateUrl('/settings/domains/{id}', {id: id}),
                    data: {
                        requesttoken: token
                    }
                }).success(function() {
                    callback();
                });
            }
        }, true
    );
}

$(document).ready(function () {
    $('.removeDomainButton').on('click', function () {
        var id = $(this).attr('data-id');
        var confirmText = $(this).attr('data-confirm');
        var token = OC.requestToken;
        var $el = $(this);

        removeDomain(id, token, confirmText, function() {
            $el.closest('tr').remove();
        });
	});
});
