export const SAMPLE_HEADER = `Delivered-To: user@example.com
Received: by 2002:a05:6000:1a83:b0:2e0:1234:5678 with SMTP id abcdefg;
        Wed, 30 Jul 2026 08:12:03 -0700 (PDT)
X-Received: by 2002:a17:902:d2c9:b0:1a1:2233:4455 with SMTP id def-mno;
        Wed, 30 Jul 2026 08:12:02 -0700 (PDT)
Return-Path: <sender@gmail.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.example.com with SMTPS id xyz123
        for <user@example.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jul 2026 08:12:01 -0700 (PDT)
Received-SPF: pass (example.com: domain of sender@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41; envelope-from="sender@gmail.com";
Authentication-Results: mx.example.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abcDEF123;
       spf=pass (example.com: domain of sender@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=sender@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1785000000; x=1785604800;
        h=to:subject:message-id:date:from:mime-version;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz1234
         5678ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789A
         BC==
Message-ID: <CADemoMessageId1234567890@mail.gmail.com>
Date: Wed, 30 Jul 2026 08:11:58 -0700
Subject: Quarterly report attached
From: Sender Name <sender@gmail.com>
To: User Name <user@example.com>
Content-Type: multipart/alternative; boundary="0000000000001"
MIME-Version: 1.0
`;
