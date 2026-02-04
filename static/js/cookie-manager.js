class CookieManager {
    constructor() {
        this.cookieBanner = null;
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        
        if (!this.getCookie('cookie_preferences_set')) {
            this.showCookieBanner();
        }
        
        // Initialize features based on saved preferences
        this.initializeFeatures();
        
        this.initialized = true;
    }

    showCookieBanner() {
        const banner = document.createElement('div');
        banner.className = 'cookie-banner';
        banner.innerHTML = `
            <div class="cookie-banner-content">
                <p class="cookie-banner-text">We use cookies to enhance your experience and analyze our site usage. By continuing to browse, you agree to our use of cookies. You can manage your preferences at any time.</p>
                <div class="cookie-banner-buttons">
                    <button class="btn btn-secondary" onclick="cookieManager.acceptEssential()">Essential Only</button>
                    <button class="btn btn-primary" onclick="cookieManager.acceptAll()">Accept All</button>
                    <a href="/cookie-policy" class="btn btn-link">Settings</a>
                </div>
            </div>
        `;
        document.body.appendChild(banner);
        this.cookieBanner = banner;
    }

    async savePreferences(preferences) {
        try {
            const response = await fetch('/save-cookie-preferences', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf_token]').value
                },
                body: JSON.stringify(preferences)
            });

            if (response.ok) {
                this.setCookie('cookie_preferences_set', 'true', 365);
                this.hideCookieBanner();
                this.initializeFeatures();
                return true;
            }
            return false;
        } catch (error) {
            console.error('Error saving preferences:', error);
            return false;
        }
    }

    async acceptAll() {
        const preferences = {
            essential: true,
            analytics: true,
            functional: true,
            marketing: true
        };
        await this.savePreferences(preferences);
    }

    async acceptEssential() {
        const preferences = {
            essential: true,
            analytics: false,
            functional: false,
            marketing: false
        };
        await this.savePreferences(preferences);
    }

    initializeFeatures() {
        const analytics = this.getCookie('analytics_cookies') === 'true';
        const marketing = this.getCookie('marketing_cookies') === 'true';
        const functional = this.getCookie('functional_cookies') === 'true';

        if (analytics) {
            // Initialize Google Analytics
            this.initializeGoogleAnalytics();
        }

        if (marketing) {
            // Initialize marketing tools
            this.initializeMarketing();
        }

        if (functional) {
            // Initialize functional features
            this.initializeFunctional();
        }
    }

    // Helper methods
    setCookie(name, value, days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${date.toUTCString()};path=/;SameSite=Lax`;
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    hideCookieBanner() {
        if (this.cookieBanner) {
            this.cookieBanner.remove();
            this.cookieBanner = null;
        }
    }

    // Feature initialization methods
    initializeGoogleAnalytics() {
        // Google Analytics Cookies will go here
        console.log('Google Analytics initialized');
    }

    initializeMarketing() {
        // Marketing Cookies will go here
        console.log('Marketing features initialized');
    }

    initializeFunctional() {
        // Functional Cookies will go here
        console.log('Functional features initialized');
    }
}

// Initialize cookie manager
const cookieManager = new CookieManager();
document.addEventListener('DOMContentLoaded', () => cookieManager.init());