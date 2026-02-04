document.addEventListener('DOMContentLoaded', function() {
    const header = document.getElementById('mainHeader');
    let lastScroll = 0;
    let heroHeight = 0;
    
    // Get hero sections height
    const heroSection = document.querySelector('.hero-section, .hero-video, .gallery-hero');
    if (heroSection) {
        heroHeight = heroSection.offsetHeight;
    }

    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        // Always show header above hero section
        if (currentScroll <= heroHeight) {
            header.classList.remove('header-hidden');
            header.classList.remove('header-scrolled');
            return;
        }
        
        // Below hero section - handle show/hide based on scroll direction
        if (currentScroll > lastScroll) {
            // Scrolling down
            header.classList.add('header-hidden');
        } else {
            // Scrolling up
            header.classList.remove('header-hidden');
            header.classList.add('header-scrolled');
        }
        
        lastScroll = currentScroll;
    });
});