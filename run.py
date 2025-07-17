#!/usr/bin/env python3
"""
Simple startup script for Box Agent Chat Flask app
"""
import sys
from importlib import import_module

def check_dependencies():
    """Check if all required dependencies are installed"""
    requirements = [
        'flask',
        'requests', 
        'pandas',
        'python-dotenv'
    ]
    
    missing = []
    for req in requirements:
        try:
            import_module(req)
        except ImportError:
            missing.append(req)
    
    if missing:
        print("❌ Missing dependencies:")
        for dep in missing:
            print(f"   - {dep}")
        print("\n💡 Install missing dependencies with:")
        print("   pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies are installed")
    return True

def main():
    print("🤖 Box Agent Chat - Flask App")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("\n🚀 Starting Flask application...")
    print("📱 App will be available at: http://localhost:5000")
    print("⌨️  Press Ctrl+C to stop\n")
    
    try:
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    except Exception as e:
        print(f"\n❌ Error starting app: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 