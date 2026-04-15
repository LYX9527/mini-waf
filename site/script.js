document.addEventListener('DOMContentLoaded', () => {
    // 1. Initial fade-up logic
    setTimeout(() => {
        document.querySelectorAll('.fade-up').forEach(el => {
            el.classList.add('visible');
        });
    }, 100);

    // 2. Scroll Reveal (Intersection Observer)
    const observerOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                
                // Trigger terminal typing effect when terminal comes into view
                if (entry.target.classList.contains('terminal-mockup') && !entry.target.dataset.typed) {
                    typeTerminal();
                    entry.target.dataset.typed = 'true';
                }
            }
        });
    }, observerOptions);

    document.querySelectorAll('.reveal').forEach(el => {
        observer.observe(el);
    });

    // 3. Mouse Glow Effect on feature cards
    document.querySelectorAll('[data-glow]').forEach(card => {
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });

    // 4. Terminal typing effect
    const terminalCode = `version: '3.8'

services:
  mini-waf:
    image: ghcr.io/lyx9527/mini-waf:master
    container_name: mini-waf
    ports:
      - "49888:48080" # WAF 服务端口
      - "49777:8081"   # 管理控制台端口
    environment:
      - DATABASE_URL=mysql://mini_waf_user:password@mysql:3306/mini_waf
      - JWT_SECRET=super_secret_waf_key_please_change
      - RUST_LOG=info
    restart: unless-stopped
    depends_on:
      mysql:
        condition: service_healthy

  mysql:
    image: mysql:8.0
    container_name: mini-waf-mysql
    environment:
      - MYSQL_ROOT_PASSWORD=rootpassword
      - MYSQL_DATABASE=mini_waf
      - MYSQL_USER=mini_waf_user
      - MYSQL_PASSWORD=password
    volumes:
      - mysql_data:/var/lib/mysql
    restart: unless-stopped
    healthcheck:
      test: [ "CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "mini_waf_user", "-ppassword" ]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  mysql_data:`;

    const terminalContainer = document.getElementById('code-terminal');
    
    function typeTerminal() {
        let i = 0;
        terminalContainer.innerHTML = '';
        function typeWriter() {
            if (i < terminalCode.length) {
                terminalContainer.innerHTML += terminalCode.charAt(i);
                i++;
                setTimeout(typeWriter, 15);
            } else {
                // Add blinking cursor
                terminalContainer.innerHTML += '<span class="cursor">_</span>';
                addCursorStyle();
            }
        }
        setTimeout(typeWriter, 500);
    }

    function addCursorStyle() {
        const style = document.createElement('style');
        style.textContent = `
            .cursor {
                animation: blink 1s step-start infinite;
                color: #ff5f56;
            }
            @keyframes blink { 50% { opacity: 0; } }
        `;
        document.head.appendChild(style);
    }
});
