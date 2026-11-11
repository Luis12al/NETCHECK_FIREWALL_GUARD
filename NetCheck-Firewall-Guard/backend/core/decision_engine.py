def decide_action(inspection_result: dict) -> str:
    """
    Determina si el paquete debe ser aceptado (ALLOW) o descartado (DROP)
    según el resultado de la inspección.
    """
    status = inspection_result.get("status")
    
    if status == "VALID":
        return "ALLOW"
    elif status == "INVALID":
        return "DROP"
    else:  # UNVERIFIED
        return "DROP"  # Política restrictiva por defecto