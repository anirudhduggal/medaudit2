#!/usr/bin/env python3
"""
Quick verification script for AI Analysis feature.
Checks that all components are properly integrated.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test that all AI-related modules can be imported."""
    print("✓ Testing imports...")
    
    try:
        from medaudit.web import ai_api
        print("  ✓ AI API module imported")
    except ImportError as e:
        print(f"  ✗ Failed to import ai_api: {e}")
        return False
    
    try:
        from medaudit.web.app import app
        print("  ✓ Main app imported")
    except ImportError as e:
        print(f"  ✗ Failed to import app: {e}")
        return False
    
    return True


def test_api_structure():
    """Test that API has the expected structure."""
    print("\n✓ Testing API structure...")
    
    from medaudit.web import ai_api
    
    # Check router exists
    assert hasattr(ai_api, 'router'), "Router not found"
    print("  ✓ Router exists")
    
    # Check expected functions
    expected_functions = [
        'save_ai_config',
        'get_ai_config',
        'chat',
        'analyze_project',
        'get_providers',
        'get_suggestions'
    ]
    
    for func_name in expected_functions:
        if hasattr(ai_api, func_name):
            print(f"  ✓ {func_name} function exists")
        else:
            print(f"  ✗ {func_name} function not found")
            return False
    
    return True


def test_app_includes_router():
    """Test that main app includes the AI router."""
    print("\n✓ Testing app integration...")
    
    from medaudit.web.app import app
    
    # Check routes
    routes = [route.path for route in app.routes]
    ai_routes = [r for r in routes if '/api/ai' in r]
    
    if len(ai_routes) > 0:
        print(f"  ✓ Found {len(ai_routes)} AI routes")
        for route in ai_routes[:5]:  # Show first 5
            print(f"    - {route}")
        if len(ai_routes) > 5:
            print(f"    ... and {len(ai_routes) - 5} more")
    else:
        print("  ✗ No AI routes found in app")
        return False
    
    return True


def test_template_has_ai_tab():
    """Test that project.html template includes AI tab."""
    print("\n✓ Testing template integration...")
    
    template_path = Path(__file__).parent.parent / "medaudit" / "web" / "templates" / "project.html"
    
    if not template_path.exists():
        print(f"  ✗ Template not found: {template_path}")
        return False
    
    content = template_path.read_text()
    
    checks = [
        ('Analyze with AI tab', 'Analyze with AI'),
        ('AI tab content', 'id="aiTab"'),
        ('AI config section', 'AI Configuration'),
        ('AI chat area', 'aiChatArea'),
        ('AI functions', 'function saveAIConfig()'),
        ('AI functions', 'function sendAIMessage()'),
    ]
    
    for check_name, search_text in checks:
        if search_text in content:
            print(f"  ✓ {check_name} found")
        else:
            print(f"  ✗ {check_name} not found")
            return False
    
    return True


def test_documentation():
    """Test that documentation exists."""
    print("\n✓ Testing documentation...")
    
    ai_guide = Path(__file__).parent.parent / "AI_ANALYSIS_GUIDE.md"
    
    if ai_guide.exists():
        print(f"  ✓ AI_ANALYSIS_GUIDE.md exists ({ai_guide.stat().st_size} bytes)")
    else:
        print("  ✗ AI_ANALYSIS_GUIDE.md not found")
        return False
    
    readme = Path(__file__).parent.parent / "README.md"
    if readme.exists():
        content = readme.read_text()
        if "AI-Powered Analysis" in content or "AI_ANALYSIS_GUIDE" in content:
            print("  ✓ README mentions AI feature")
        else:
            print("  ✗ README doesn't mention AI feature")
            return False
    
    return True


def main():
    """Run all verification tests."""
    print("=" * 60)
    print("AI Analysis Feature Verification")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_api_structure,
        test_app_includes_router,
        test_template_has_ai_tab,
        test_documentation
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n✗ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("\n" + "=" * 60)
    print(f"Results: {sum(results)}/{len(results)} tests passed")
    print("=" * 60)
    
    if all(results):
        print("\n✅ All verification checks passed!")
        print("\nNext steps:")
        print("1. Start the web server: python3 -m medaudit web --port 8080")
        print("2. Open http://localhost:8080 in your browser")
        print("3. Navigate to a project and click 'Analyze with AI' tab")
        print("4. Configure your AI provider (OpenAI, Anthropic, or local)")
        print("5. Start analyzing!")
        print("\nFor local/privacy-focused AI:")
        print("- Install Ollama: https://ollama.ai")
        print("- Run: ollama pull llama3.1")
        print("- Use 'Custom' provider with base URL: http://localhost:11434/v1")
        return 0
    else:
        print("\n❌ Some verification checks failed")
        print("Please review the errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
