
import csv
from datetime import datetime, timezone
from pathlib import Path

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rcode

# Servidores y dependencias del laboratorio
ZONAS = {
    ".": ("172.30.0.10", None),
    "unsigned.": ("172.30.0.20", "."),
    "alpha.unsigned.": ("172.30.0.30", "unsigned."),
    "delta.unsigned.": ("172.30.0.80", "unsigned."),
    "epsilon.unsigned.": ("172.30.0.81", "unsigned."),
    "zeta.unsigned.": ("172.30.0.82", "unsigned."),
    "signed.": ("172.30.0.40", "."),
    "beta.signed.": ("172.30.0.50", "signed."),
    "gamma.signed.": ("172.30.0.60", "signed."),
    "theta.signed.": ("172.30.0.83", "signed."),
    "iota.signed.": ("172.30.0.84", "signed."),
    "kappa.signed.": ("172.30.0.85", "signed."),
    "test.": ("172.30.0.70", "."),
    "sinds.test.": ("172.30.0.86", "test."),
    "dserror.test.": ("172.30.0.87", "test."),
    "expirado.test.": ("172.30.0.88", "test."),
}

TIPOS_DS = {1: "SHA1", 2: "SHA256", 4: "SHA384"}
AHORA = datetime.now(timezone.utc)


def consultar(ip, dominio, tipo, recursivo=False):
    pregunta = dns.message.make_query(
        dominio, tipo, want_dnssec=True
    )

    if not recursivo:
        pregunta.flags &= ~dns.flags.RD

    respuesta = dns.query.udp(pregunta, ip, timeout=3)

    if respuesta.flags & dns.flags.TC:
        respuesta = dns.query.tcp(pregunta, ip, timeout=3)

    return respuesta


def obtener(respuesta, tipo, nombre=None, cubre=None):
    codigo = dns.rdatatype.from_text(tipo)
    nombre_dns = dns.name.from_text(nombre) if nombre else None

    for registro in respuesta.answer:
        if registro.rdtype != codigo:
            continue

        if nombre_dns is not None and registro.name != nombre_dns:
            continue

        if cubre is not None:
            if registro.covers != dns.rdatatype.from_text(cubre):
                continue

        return registro

    return None


def validar_firma(registros, firma, claves, dominio):
    if not registros or not firma or not claves:
        return "SIN DATOS"

    try:
        dns.dnssec.validate(
            registros,
            firma,
            {dns.name.from_text(dominio): claves}
        )
        return "VALIDA"

    except Exception as error:
        return "INVALIDA: " + str(error)


def revisar(dominio, ip, padre):
    print("\n" + "=" * 55)
    print("DOMINIO:", dominio)

    if padre:
        print("DEPENDENCIA:", padre, "->", dominio)
    else:
        print("DOMINIO RAIZ")

    print("SERVIDOR:", ip)

    fila = {
        "dominio": dominio,
        "servidor": ip,
        "padre": padre or "",
        "dnskey": 0,
        "ksk": "",
        "zsk": "",
        "algoritmos": "",
        "firma_dnskey": "",
        "firma_soa": "",
        "ds": "",
        "ttl_dnskey": "",
        "ttl_ds": "",
        "ttl_soa": "",
        "negacion": "",
        "recursivo1": "",
        "recursivo2": ""
    }

    try:
        # 1. REGISTROS DNSKEY
        respuesta = consultar(ip, dominio, "DNSKEY")
        claves = obtener(respuesta, "DNSKEY", dominio)
        firmas = obtener(respuesta, "RRSIG", dominio, "DNSKEY")

        if claves:
            fila["dnskey"] = len(claves)
            fila["ttl_dnskey"] = claves.ttl

            print("\nDNSKEY | TTL:", claves.ttl)
            algoritmos = set()

            for clave in claves:
                identificador = dns.dnssec.key_id(clave)
                tipo = "KSK" if (clave.flags & 1) else "ZSK"

                print(
                    tipo,
                    "ID:", identificador,
                    "Algoritmo:", clave.algorithm,
                    "Flags:", clave.flags,
                    "Protocolo:", clave.protocol
                )

                campo = tipo.lower()
                if fila[campo]:
                    fila[campo] += ","
                fila[campo] += str(identificador)

                algoritmos.add(clave.algorithm)

            fila["algoritmos"] = ",".join(
                map(str, sorted(algoritmos))
            )

            # 2. VERIFICACION CRIPTOGRAFICA DNSKEY
            fila["firma_dnskey"] = validar_firma(
                claves, firmas, claves, dominio
            )

            print("Firmas DNSKEY:", fila["firma_dnskey"])

            if firmas:
                print("\nRRSIG DNSKEY")

                for firma in firmas:
                    inicio = datetime.fromtimestamp(
                        firma.inception, timezone.utc
                    )
                    fin = datetime.fromtimestamp(
                        firma.expiration, timezone.utc
                    )

                    vigente = inicio <= AHORA <= fin

                    print("Firmante:", firma.signer)
                    print("Clave:", firma.key_tag)
                    print("Inicio:", inicio)
                    print("Expira:", fin)
                    print("Vigente:", vigente)

        else:
            print("\nDNSKEY: No disponible")

        # 3. REGISTROS SOA Y SUS FIRMAS
        respuesta_soa = consultar(ip, dominio, "SOA")
        soa = obtener(respuesta_soa, "SOA", dominio)
        firma_soa = obtener(
            respuesta_soa, "RRSIG", dominio, "SOA"
        )

        if soa:
            fila["ttl_soa"] = soa.ttl
            print("\nTTL SOA:", soa.ttl)

            if claves:
                fila["firma_soa"] = validar_firma(
                    soa, firma_soa, claves, dominio
                )
                print("Firma SOA:", fila["firma_soa"])

            if firma_soa:
                for firma in firma_soa:
                    vencimiento = datetime.fromtimestamp(
                        firma.expiration, timezone.utc
                    )

                    print("RRSIG SOA expira:", vencimiento)
                    print("Vencida:", AHORA > vencimiento)

        # 4. REGISTROS DS Y DEPENDENCIA PADRE-HIJO
        print("\nCADENA DS")

        if padre:
            ip_padre = ZONAS[padre][0]

            respuesta_ds = consultar(
                ip_padre, dominio, "DS"
            )

            registros_ds = obtener(
                respuesta_ds, "DS", dominio
            )

            if registros_ds:
                fila["ttl_ds"] = registros_ds.ttl
                print("TTL DS:", registros_ds.ttl)

                coincide = False

                for ds in registros_ds:
                    print("DS publicado:", ds.to_text())

                    if not claves:
                        continue

                    metodo = TIPOS_DS.get(ds.digest_type)

                    if not metodo:
                        print(
                            "Digest no implementado:",
                            ds.digest_type
                        )
                        continue

                    for clave in claves:
                        try:
                            calculado = dns.dnssec.make_ds(
                                dominio, clave, metodo
                            )

                            # Comparacion corregida
                            mismo = (
                                calculado.key_tag == ds.key_tag
                                and calculado.algorithm == ds.algorithm
                                and calculado.digest_type == ds.digest_type
                                and calculado.digest == ds.digest
                            )

                            if calculado.key_tag == ds.key_tag:
                                print(
                                    "DS calculado:",
                                    calculado.to_text()
                                )

                            if mismo:
                                coincide = True

                        except Exception as error:
                            print(
                                "Error calculando DS:",
                                error
                            )

                if coincide:
                    fila["ds"] = "COINCIDE"
                else:
                    fila["ds"] = "NO COINCIDE"

                print(
                    "Coincidencia DS-DNSKEY:",
                    fila["ds"]
                )

            else:
                fila["ds"] = "SIN DS"
                print(
                    "Sin DS publicado en el padre."
                )
                print(
                    "Falta verificar la negacion autenticada."
                )

        else:
            fila["ds"] = "RAIZ / ANCLA EXTERNA"
            print(
                "La raiz requiere un ancla de confianza."
            )

        # 5. NSEC Y NSEC3
        print("\nREGISTROS DE NEGACION")

        respuesta_nsec = consultar(
            ip, dominio, "NSEC"
        )
        nsec = obtener(
            respuesta_nsec, "NSEC", dominio
        )

        respuesta_nsec3 = consultar(
            ip, dominio, "NSEC3PARAM"
        )
        nsec3 = obtener(
            respuesta_nsec3, "NSEC3PARAM", dominio
        )

        if nsec3:
            fila["negacion"] = "NSEC3"
            print("NSEC3PARAM presente: SI")
            print("TTL:", nsec3.ttl)

        elif nsec:
            fila["negacion"] = "NSEC"
            print("NSEC presente: SI")
            print("TTL:", nsec.ttl)

        else:
            fila["negacion"] = "NO DETERMINADO"
            print("Mecanismo no determinado")

        # 6. COMPARACION ENTRE RECURSIVOS
        print("\nSERVIDORES RECURSIVOS")

        servidores = [
            ("Sin validacion", "172.30.0.100", "recursivo1"),
            ("Con validacion", "172.30.0.101", "recursivo2")
        ]

        for etiqueta, servidor, campo in servidores:
            try:
                respuesta_r = consultar(
                    servidor, dominio, "SOA",
                    recursivo=True
                )

                estado = dns.rcode.to_text(
                    respuesta_r.rcode()
                )

                autenticado = bool(
                    respuesta_r.flags & dns.flags.AD
                )

                resultado = estado

                if autenticado:
                    resultado += " AD"

                fila[campo] = resultado
                print(etiqueta + ":", resultado)

            except Exception as error:
                fila[campo] = "ERROR: " + str(error)
                print(etiqueta + ":", fila[campo])

    except Exception as error:
        print(
            "ERROR DE CONSULTA:",
            type(error).__name__,
            str(error)
        )

    return fila


# 7. EJECUTAR LAS VERIFICACIONES
resultados = []

for dominio, (ip, padre) in ZONAS.items():
    resultado = revisar(dominio, ip, padre)
    resultados.append(resultado)


# 8. GUARDAR METRICAS EN FORMATO TSV
archivo_salida = Path.home() / "metricas_dnssec.tsv"

with archivo_salida.open(
    "w",
    encoding="utf-8",
    newline=""
) as archivo:

    escritor = csv.DictWriter(
        archivo,
        fieldnames=list(resultados[0]),
        delimiter="\t"
    )

    escritor.writeheader()
    escritor.writerows(resultados)


print("\n" + "=" * 55)
print("VERIFICACION FINALIZADA")
print("Metricas guardadas en:", archivo_salida)
print("=" * 55)

print(
    "IMPORTANTE: La coincidencia DS y las firmas locales"
)
print(
    "no garantizan por si solas la validacion completa"
)
print(
    "de la cadena de confianza DNSSEC."
)
