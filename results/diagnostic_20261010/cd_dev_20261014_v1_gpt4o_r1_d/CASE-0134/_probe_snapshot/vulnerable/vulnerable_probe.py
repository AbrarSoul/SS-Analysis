def parse_native_url(url):
    """
    Support https://maker.ifttt.com/use/WEBHOOK_ID/EVENT_ID
    """

    result_renamed = re.match(
        r'^https?://maker\.ifttt\.com/use/'
        r'(?P<webhook_id>[A-Z0-9_-]+)'
        r'/?(?P<events>([A-Z0-9_-]+/?)+)?'
        r'/?(?P<params>\?.+)?$', url, re.I)

    if result_renamed:
        return NotifyIFTTT.parse_url(
            '{schema}://{webhook_id}{events}{params}'.format(
                schema=NotifyIFTTT.secure_protocol,
                webhook_id=result_renamed.group('webhook_id'),
                events='' if not result_renamed.group('events')
                else '@{}'.format(result_renamed.group('events')),
                params='' if not result_renamed.group('params')
                else result_renamed.group('params')))

    return None