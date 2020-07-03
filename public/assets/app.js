/* globals document, $, moment */
/* eslint no-invalid-this:0 */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        for (let block of document.querySelectorAll('.flash-messages')) {
            block.parentNode.removeChild(block);
        }
    }, 10 * 1000);

    $('input.daterange').each(function () {
        const input = $(this);
        const format = 'YYYY/MM/DD';
        $(this).daterangepicker(
            {
                startDate: $(this).data('start'),
                endDate: $(this).data('end'),
                opens: 'right',
                locale: {
                    format
                }
            },
            function (start, end, label) {
                $(`#${input.data('startTarget')}`).val(start.format(format));
                $(`#${input.data('endTarget')}`).val(end.format(format));
                console.log(
                    input.data('startTarget'),
                    'New date range selected: ' + start.format('YYYY-MM-DD') + ' to ' + end.format('YYYY-MM-DD') + ' (predefined range: ' + label + ')'
                );
            }
        );
    });

    $('input.datepick').daterangepicker({
        singleDatePicker: true,
        opens: 'right',
        locale: {
            format: 'YYYY/MM/DD'
        }
    });

    for (let elm of document.querySelectorAll('.timestr')) {
        elm.textContent = moment(elm.title).format('ll');
    }

    $(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });
});
