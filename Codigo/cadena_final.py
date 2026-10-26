
import csv
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.rcode

# Arquitectura del laboratorio
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

ANCLA = Path(
    "/etc/bind/dns-lab/root/zones/K.+013+12203.key"
)

SALIDA = Path.home() / "cadena_dnssec.tsv"

HASHES = {
    1: "SHA1",
    2: "SHA256",
    4: "SHA384"
}


def consulta(ip, zona, tipo):
    pregunta = dns.message.make_query(
        zona, tipo, want_dnssec=True
    )
    pregunta.flags &= ~dns.flags.RD

    respuesta = dns.query.udp(
        pregunta, ip, timeout=4
    )

    if respuesta.flags & dns.flags.TC:
        respuesta = dns.query.tcp(
            pregunta, ip, timeout=4
        )

    if respuesta.rcode() != dns.rcode.NOERROR:
        raise ValueError(
            f"{zona} {tipo}: "
            f"{dns.rcode.to_text(respuesta.rcode())}"
        )

    if not respuesta.flags & dns.flags.AA:
        raise ValueError(
            f"{ip}: respuesta no autoritativa"
        )

    return respuesta


def obtener(respuesta, zona, tipo, cubre=None):
    nombre = dns.name.from_text(zona)
    numero = dns.rdatatype.from_text(tipo)

    cobertura = (
        dns.rdatatype.from_text(cubre)
        if cubre else None
    )

    grupos = (
        list(respuesta.answer)
        + list(respuesta.authority)
    )

    for grupo in grupos:
        if (
            grupo.name == nombre
            and grupo.rdtype == numero
        ):
            if (
                cobertura is None
                or grupo.covers == cobertura
            ):
                return grupo

    return None


def validar(rrset, rrsig, firmante, keys):
    if rrset is None or rrsig is None:
        raise ValueError(
            "Falta registro o firma RRSIG"
        )

    dns.dnssec.validate(
        rrset,
        rrsig,
        {dns.name.from_text(firmante): keys}
    )


def cargar_ancla():
    # Leer directamente la KSK publica de la raiz.
    # No se utilizan valores hexadecimales copiados.

    if not ANCLA.exists():
        raise FileNotFoundError(
            f"Falta el archivo {ANCLA}"
        )

    contenido = ANCLA.read_text(
        encoding="utf-8"
    )

    for linea in contenido.splitlines():
        partes = linea.split(";", 1)[0].split()

        if "DNSKEY" not in partes:
            continue

        indice = partes.index("DNSKEY")

        clave = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            " ".join(partes[indice + 1:])
        )

        if (
            clave.flags == 257
            and clave.protocol == 3
            and clave.algorithm == 13
            and dns.dnssec.key_id(clave) == 12203
        ):
            return clave

    raise ValueError(
        "KSK 12203 no encontrada en el ancla"
    )


def comprobar_soa(zona, ip, keys=None):
    respuesta = consulta(ip, zona, "SOA")
    soa = obtener(respuesta, zona, "SOA")

    if soa is None:
        raise ValueError("No existe SOA")

    if keys is not None:
        firma = obtener(
            respuesta, zona, "RRSIG", "SOA"
        )
        validar(soa, firma, zona, keys)

    return soa.ttl


def negar_ds(respuesta, zona, padre, keys_padre):
    nsec = obtener(
        respuesta, zona, "NSEC"
    )
    firma = obtener(
        respuesta, zona, "RRSIG", "NSEC"
    )

    validar(
        nsec, firma, padre, keys_padre
    )

    for registro in nsec:
        tipos = set(
            registro.to_text().upper().split()[1:]
        )

        if (
            "NS" in tipos
            and "DS" not in tipos
        ):
            return nsec.ttl

    raise ValueError(
        "NSEC no demuestra ausencia de DS"
    )


def ksk_coincidentes(zona, registros_ds, dnskeys):
    buenas = []

    for clave in dnskeys:
        if (
            clave.flags != 257
            or clave.protocol != 3
        ):
            continue

        for ds in registros_ds:
            algoritmo = HASHES.get(
                ds.digest_type
            )

            if not algoritmo:
                continue

            try:
                calculado = dns.dnssec.make_ds(
                    zona,
                    clave,
                    algoritmo,
                    validating=True
                )

                coincide = (
                    calculado.key_tag == ds.key_tag
                    and calculado.algorithm == ds.algorithm
                    and calculado.digest_type == ds.digest_type
                    and calculado.digest == ds.digest
                )

                if coincide:
                    buenas.append(clave)
                    break

            except (
                dns.dnssec.UnsupportedAlgorithm,
                dns.dnssec.DeniedByPolicy
            ):
                continue

    if not buenas:
        raise ValueError(
            "DS del padre NO coincide con KSK del hijo"
        )

    return dns.rdataset.from_rdata_list(
        dnskeys.ttl, buenas
    )


def ejecutar():
    ancla = cargar_ancla()

    print(
        "ANCLA PUBLICA:",
        dns.dnssec.key_id(ancla)
    )

    resultados = {}

    for zona, (ip, padre) in ZONAS.items():

        fila = {
            "dominio": zona,
            "padre": padre or "-",
            "estado": "",
            "detalle": "",
            "ttl_ds": "",
            "ttl_dnskey": "",
            "ttl_soa": ""
        }

        keys_verificadas = None

        print("\n" + "=" * 45)
        print("DOMINIO:", zona)

        try:
            # RAIZ: verificar con KSK local

            if padre is None:
                respuesta = consulta(
                    ip, zona, "DNSKEY"
                )

                keys = obtener(
                    respuesta, zona, "DNSKEY"
                )

                if (
                    keys is None
                    or ancla not in keys
                ):
                    raise ValueError(
                        "KSK anclada no aparece en raiz"
                    )

                solo_ancla = (
                    dns.rdataset.from_rdata_list(
                        keys.ttl, [ancla]
                    )
                )

                firma = obtener(
                    respuesta,
                    zona,
                    "RRSIG",
                    "DNSKEY"
                )

                validar(
                    keys,
                    firma,
                    zona,
                    solo_ancla
                )

                keys_verificadas = keys

                fila.update(
                    estado="SEGURO",
                    detalle="Raiz autenticada",
                    ttl_dnskey=keys.ttl
                )

            # Delegacion insegura heredada

            elif (
                resultados[padre]["estado"]
                == "INSEGURO"
            ):
                fila.update(
                    estado="INSEGURO",
                    detalle="Hereda delegacion insegura"
                )

            # Padre sin validar

            elif (
                resultados[padre]["estado"]
                != "SEGURO"
            ):
                fila.update(
                    estado="INDETERMINADO",
                    detalle="Padre no validado"
                )

            # Delegacion desde padre seguro

            else:
                ip_padre = ZONAS[padre][0]

                keys_padre = (
                    resultados[padre]["claves"]
                )

                respuesta_ds = consulta(
                    ip_padre, zona, "DS"
                )

                ds = obtener(
                    respuesta_ds, zona, "DS"
                )

                if ds is None:
                    ttl = negar_ds(
                        respuesta_ds,
                        zona,
                        padre,
                        keys_padre
                    )

                    fila.update(
                        estado="INSEGURO",
                        detalle="Ausencia DS probada con NSEC",
                        ttl_ds=ttl
                    )

                else:
                    firma_ds = obtener(
                        respuesta_ds,
                        zona,
                        "RRSIG",
                        "DS"
                    )

                    validar(
                        ds,
                        firma_ds,
                        padre,
                        keys_padre
                    )

                    respuesta_keys = consulta(
                        ip, zona, "DNSKEY"
                    )

                    keys = obtener(
                        respuesta_keys,
                        zona,
                        "DNSKEY"
                    )

                    if keys is None:
                        raise ValueError(
                            "DS presente pero DNSKEY ausente"
                        )

                    aceptadas = ksk_coincidentes(
                        zona, ds, keys
                    )

                    firma_keys = obtener(
                        respuesta_keys,
                        zona,
                        "RRSIG",
                        "DNSKEY"
                    )

                    validar(
                        keys,
                        firma_keys,
                        zona,
                        aceptadas
                    )

                    keys_verificadas = keys

                    fila.update(
                        estado="SEGURO",
                        detalle="DS, DNSKEY y RRSIG validos",
                        ttl_ds=ds.ttl,
                        ttl_dnskey=keys.ttl
                    )

            # Verificar SOA y firma

            if fila["estado"] in (
                "SEGURO", "INSEGURO"
            ):
                fila["ttl_soa"] = comprobar_soa(
                    zona,
                    ip,
                    keys_verificadas
                )

        except (dns.exception.Timeout, OSError) as error:
            fila.update(
                estado="ERROR",
                detalle=str(error)
            )

        except Exception as error:
            padre_seguro = (
                padre is not None
                and resultados.get(
                    padre, {}
                ).get("estado") == "SEGURO"
            )

            estado = (
                "BOGUS" if padre_seguro
                else "ERROR"
            )

            fila.update(
                estado=estado,
                detalle=str(error)
            )

        fila["claves"] = keys_verificadas
        resultados[zona] = fila

        print(
            fila["estado"],
            "-",
            fila["detalle"]
        )

    # Exportar resultados

    columnas = [
        "dominio",
        "padre",
        "estado",
        "detalle",
        "ttl_ds",
        "ttl_dnskey",
        "ttl_soa"
    ]

    with SALIDA.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as archivo:

        escritor = csv.DictWriter(
            archivo,
            fieldnames=columnas,
            delimiter="\t"
        )

        escritor.writeheader()

        for fila in resultados.values():
            escritor.writerow(
                {c: fila[c] for c in columnas}
            )

    print("\nVERIFICACION FINALIZADA")
    print("Archivo:", SALIDA)


if __name__ == "__main__":
    ejecutar()
