package com.example.securityex.view

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import androidx.databinding.DataBindingUtil
import com.example.securityex.R
import com.example.securityex.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
        binding.mainActivity = this@MainActivity

        supportFragmentManager.beginTransaction().apply {
            add(R.id.activity_main_ecdh_fragment_container, EcdhFragment())
            add(R.id.activity_main_aes_fragment_container, AesFragment())
            commit()
        }
    }
}