#!/usr/bin/env python3
"""
Vulnerable AI Banking Application - Educational Demo
IMPORTANT: This application is intentionally vulnerable for educational purposes only!
"""

import os
import sys
from app import app

def main():
    print("🔓 Starting Vulnerable AI Banking Application")
    print("=" * 60)
    print("⚠️  WARNING: This application contains intentional vulnerabilities")
    print("   for educational and training purposes only!")
    print("   DO NOT use in production environments!")
    print("=" * 60)
    print()
    print("🔑 Test Accounts (password: testpass123):")
    print("   • admin (ID: 10) - Admin privileges")
    print("   • johndoe (ID: 1) - Regular user") 
    print("   • janesmith (ID: 2) - Regular user")
    print("   • superadmin (ID: 20) - Super admin")
    print()
    print("🏦 Account Numbers for Testing:")
    print("   • 123456789 (John's account)")
    print("   • 987654321 (Jane's account)")
    print("   • 555666777 (Admin's account)")
    print("   • 111222333 (Super admin's account)")
    print()
    print("🧪 Vulnerability Testing Guide:")
    print("   1. Register/Login with test accounts")
    print("   2. Try user IDs divisible by 10 for admin access")
    print("   3. Explore /profile?user_id=X for IDOR attacks")
    print("   4. Test AI prompt injection at /banko")
    print("   5. Test authorization bypass in /transfer (transfer from any account)")
    print("   6. Test negative amounts in /transfer")
    print("   7. Test XSS in profile bio field")
    print("   8. Use 'Force Admin' checkbox in /benefits")
    print()
    print("📖 See VULNERABILITY_GUIDE.md for complete testing instructions")
    print("=" * 60)
    print()
    
    # Start the Flask application
    try:
        debug_mode = os.environ.get('FLASK_DEBUG', '0') in ('1', 'true', 'True', 'on', 'ON')
        host = os.environ.get('APP_HOST', '127.0.0.1')
        port = int(os.environ.get('APP_PORT', '5055'))
        app.run(host=host, port=port, debug=debug_mode, use_reloader=False)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
