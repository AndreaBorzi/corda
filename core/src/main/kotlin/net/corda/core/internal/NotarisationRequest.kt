package net.corda.core.internal

import net.corda.core.contracts.StateRef
import net.corda.core.crypto.DigitalSignature
import net.corda.core.crypto.SecureHash
import net.corda.core.flows.NotaryFlow
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.serialize
import net.corda.core.transactions.CoreTransaction
import net.corda.core.transactions.SignedTransaction

/**
 * A notarisation request specifies a list of states to consume and the id of the consuming transaction. Its primary
 * purpose is for notarisation traceability – a signature over the notarisation request, [NotarisationRequestSignature],
 * allows a notary to prove that a certain party requested the consumption of a particular state.
 *
 * While the signature must be retained, the notarisation request does not need to be transferred or stored anywhere - it
 * can be built from a [SignedTransaction] or a [CoreTransaction]. The notary can recompute it from the committed states index.
 *
 * In case there is a need to prove that a party spent a particular state, the notary will:
 * 1) Locate the consuming transaction id in the index, along with all other states consumed in the same transaction.
 * 2) Build a [NotarisationRequest].
 * 3) Locate the [NotarisationRequestSignature] for the transaction id. The signature will contain the signing public key.
 * 4) Demonstrate the signature verifies against the request.
 */
@CordaSerializable
data class NotarisationRequest(val inputStates: List<StateRef>, val transactionId: SecureHash) {
    companion object {
        // Sorts in ascending order first by transaction hash, then by output index.
        private val stateRefComparator = compareBy<StateRef>({ it.txhash }, { it.index })
    }

    fun generateSignature(serviceHub: ServiceHub): NotarisationRequestSignature {
        val bytesToSign = generateBytesToSign(inputStates, transactionId)
        val signature = with(serviceHub) {
            val myLegalIdentity = myInfo.legalIdentitiesAndCerts.first().owningKey
            keyManagementService.sign(bytesToSign, myLegalIdentity)
        }
        return NotarisationRequestSignature(signature)
    }

    fun verifySignature(requestSignature: NotarisationRequestSignature, intendedSigner: Party) {
        val signature = requestSignature.digitalSignature
        require(intendedSigner.owningKey == signature.by) { "Notarisation request for $transactionId not signed by the requesting party" }
        val expectedSignedBytes = generateBytesToSign(inputStates, transactionId)
        signature.verify(expectedSignedBytes)
    }

    private fun generateBytesToSign(inputStates: List<StateRef>, txId: SecureHash): ByteArray {
        val sortedInputs = inputStates.sortedWith(stateRefComparator)
        return NotarisationRequest(sortedInputs, txId).serialize().bytes
    }
}

/** A wrapper around a digital signature used for notarisation requests. */
@CordaSerializable
data class NotarisationRequestSignature(val digitalSignature: DigitalSignature.WithKey)

/** Container for the transaction and notarisation request signature that are sent by a client to a notary service. */
@CordaSerializable
data class NotarisationPayload(private val transaction: Any, val requestSignature: NotarisationRequestSignature) {
    init {
        require(transaction is SignedTransaction || transaction is CoreTransaction)
    }
    val signedTransaction get() = transaction as SignedTransaction
    val coreTransaction get() = transaction as CoreTransaction
}

fun NotaryFlow.Service.validateRequest(request: NotarisationRequest, signature: NotarisationRequestSignature) {
    val requestingParty = otherSideSession.counterparty
    request.verifySignature(signature, requestingParty)
    // TODO: persist the signature for traceability.
}