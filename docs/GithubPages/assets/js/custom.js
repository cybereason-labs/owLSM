/**
 * owLSM Documentation - Custom JavaScript
 * Handles tabs, smooth scrolling, and interactive code highlighting
 */

document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initSmoothScroll();
    initCodeHighlighting();
});

/**
 * Initialize tab functionality
 */
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabContainer = this.closest('.tab-container');
            const targetTab = this.getAttribute('data-tab');
            
            // Remove active class from all buttons and content in this container
            tabContainer.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            tabContainer.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Add active class to clicked button and corresponding content
            this.classList.add('active');
            const targetContent = tabContainer.querySelector('#' + targetTab);
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
}

/**
 * Initialize smooth scrolling for anchor links
 */
function initSmoothScroll() {
    // Handle clicks on code links and regular anchor links
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a[href^="#"]');
        if (!link) return;
        
        const targetId = link.getAttribute('href').substring(1);
        const targetElement = document.getElementById(targetId);
        
        if (targetElement) {
            e.preventDefault();
            
            // Calculate offset for fixed header
            const headerOffset = 80;
            const elementPosition = targetElement.getBoundingClientRect().top;
            const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
            
            window.scrollTo({
                top: offsetPosition,
                behavior: 'smooth'
            });
            
            // Update URL hash without jumping
            history.pushState(null, null, '#' + targetId);
            
            // Highlight the target section briefly
            highlightSection(targetElement);
        }
    });
    
    // Handle initial hash on page load
    if (window.location.hash) {
        setTimeout(function() {
            const targetId = window.location.hash.substring(1);
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                const headerOffset = 80;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
                
                highlightSection(targetElement);
            }
        }, 100);
    }
}

/**
 * Briefly highlight a section after scrolling to it
 */
function highlightSection(element) {
    // Find the config-section or rule-section container
    let sectionElement = element.nextElementSibling;
    if (sectionElement && (sectionElement.classList.contains('config-section') || 
                          sectionElement.classList.contains('rule-section'))) {
        sectionElement.style.transition = 'background-color 0.3s ease';
        sectionElement.style.backgroundColor = 'rgba(114, 83, 237, 0.1)';
        
        setTimeout(function() {
            sectionElement.style.backgroundColor = '';
        }, 1500);
    }
}

/**
 * Initialize code link highlighting on hover
 */
function initCodeHighlighting() {
    const codeLinks = document.querySelectorAll('.code-link');
    
    codeLinks.forEach(link => {
        link.addEventListener('mouseenter', function() {
            this.style.backgroundColor = 'rgba(108, 99, 255, 0.2)';
            this.style.borderRadius = '3px';
            this.style.padding = '0 2px';
        });
        
        link.addEventListener('mouseleave', function() {
            this.style.backgroundColor = '';
            this.style.padding = '';
        });
    });
}

/**
 * Utility: Scroll to element by ID
 */
function scrollToElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        const headerOffset = 80;
        const elementPosition = element.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
        
        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    }
}
