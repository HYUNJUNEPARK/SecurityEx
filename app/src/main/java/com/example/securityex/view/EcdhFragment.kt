package com.example.securityex.view

import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import com.example.securityex.R
import com.example.securityex.alg.EcdhAlg
import com.example.securityex.consts.AppConst.TAG
import com.example.securityex.databinding.FragmentEcdhBinding

class EcdhFragment : Fragment() {
    private var _binding: FragmentEcdhBinding? = null
    private val binding get() = _binding!!

    private val ecdhAlg by lazy { EcdhAlg.getInstance(requireContext()) }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = DataBindingUtil.inflate(inflater, R.layout.fragment_ecdh, container, false)
        binding.ecdhFragment = this@EcdhFragment
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    fun onClickedEvent1() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ecdhAlg!!.generateECKeyPair()
        }
    }

    fun onClickedEvent2() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val publicKey = ecdhAlg!!.getECPublicKey()
            Log.d(TAG, "onClickedEvent2: $publicKey")


        }
    }
}