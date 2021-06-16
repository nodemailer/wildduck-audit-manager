/* globals document, $, moment, FileReader */
/* eslint no-invalid-this:0, prefer-arrow-callback:0 */
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

    for (let elm of document.querySelectorAll('.datetimestr')) {
        elm.textContent = moment(elm.title).calendar(null, {
            sameDay: 'HH:MM',
            lastDay: 'D. MMM HH:MM',
            nextDay: 'D. MMM',
            lastWeek: 'D. MMM',
            nextWeek: 'D. MMM',
            sameElse: 'DD/MM/YY'
        });
    }

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

    for (let elm of document.querySelectorAll('.fulltimestr')) {
        elm.textContent = moment(elm.title).format('YYYY-MM-DD HH:mm');
    }

    $(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });

    function dropfile(elm, file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            elm.value = (e.target.result || '').trim();
            elm.focus();
            elm.select();
        };
        reader.readAsText(file, 'UTF-8');
    }

    for (let elm of document.querySelectorAll('.droptxt')) {
        elm.addEventListener('dragenter', () => {
            elm.classList.add('dragover');
        });

        elm.addEventListener('dragleave', () => {
            elm.classList.remove('dragover');
        });

        elm.addEventListener('drop', e => {
            e.preventDefault();
            elm.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            dropfile(elm, file);
        });

        elm.addEventListener('click', () => {
            elm.focus();
            elm.select();
        });
    }

    for (let elm of document.querySelectorAll('.click-once')) {
        elm.addEventListener('click', () => {
            setTimeout(() => {
                $(elm).tooltip('dispose');
                elm.parentNode.removeChild(elm);
            }, 100);
        });
    }
});
