def login_flow():
    camera.open()
    choice = prompt_user(["Draw Seal", "Scan Tattoo"])
    
    if choice == "Draw Seal":
        seal = capture_gesture()
        seal_hash = hash(seal)
        verify(seal_hash)
        
    elif choice == "Scan Tattoo":
        tattoo_code = scan_qr()
        verify(tattoo_code)
        
    elif choice == "Dual":
        seal = capture_gesture()
        tattoo_code = scan_qr()
        verify_dual(hash(seal), tattoo_code)
    
    if verified:
        grant_access()
    else:
        deny_access()
