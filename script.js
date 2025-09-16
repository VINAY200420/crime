const map = L.map('map').setView([12.9716, 77.5946], 13);

// Add tile layer
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

// Load crime data from Flask
fetch('/data')
  .then(res => res.json())
  .then(points => {
    const heatData = points.map(p => [p.lat, p.lng, p.intensity]);
    L.heatLayer(heatData, { radius: 25, blur: 20 }).addTo(map);

    document.getElementById("total-count").textContent = points.length;
    document.getElementById("risk-count").textContent = points.filter(p => p.intensity >= 0.8).length;
  })
  .catch(err => {
    alert("Error loading heatmap data");
    console.error(err);
  });
