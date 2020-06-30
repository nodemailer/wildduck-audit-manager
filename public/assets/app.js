/* globals document */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        for (let block of document.querySelectorAll('.flash-messages')) {
            block.parentNode.removeChild(block);
        }
    }, 10 * 1000);
});
