document.addEventListener('DOMContentLoaded', () => {
    const videoElement = document.querySelector('#player');

    if (!videoElement || typeof Plyr === 'undefined') {
        return;
    }

    const player = new Plyr('#player', {
        controls: [
            'play-large',
            'play',
            'progress',
            'current-time',
            'duration',
            'mute',
            'volume',
            'settings',
            'fullscreen'
        ],
        settings: ['speed']
    });

    console.log('Plyr video player initialized successfully.');
});
